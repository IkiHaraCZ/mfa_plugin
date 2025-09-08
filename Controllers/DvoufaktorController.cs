using Datona.MobilniCisnik.Server;
using Datona.MobilniCisnik.Web.Code;
using Datona.Web.Code;
using Datona.Web.Code.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Datona.Web.Controllers
{
    public class DvoufaktorController : Controller
    {
        private readonly IMfaStore _store;
        private readonly ITotpService _totp;
        private readonly ISecretProtector _protector;
        private readonly IBackupCodeService _backup;
        private readonly MfaVolby _opts;
        private readonly GcrHelper _gcr;
        private readonly ILogger<DvoufaktorController> _log;

        public DvoufaktorController(
            IMfaStore store,
            ITotpService totp,
            ISecretProtector protector,
            IBackupCodeService backup,
            MfaVolby opts,
            GcrHelper gcr,
            ILogger<DvoufaktorController> log)
        {
            _store = store;
            _totp = totp;
            _protector = protector;
            _backup = backup;
            _opts = opts;
            _gcr = gcr;
            _log = log;
        }

        private long GetCurrentUserIdOrThrow()
        {
            var aspx = Request.Cookies[".ASPXAUTH"];
            var ac = !string.IsNullOrEmpty(aspx)
                ? AuthCookie.AuthenticationClaim(aspx)
                : null;
            if (ac == null) throw new InvalidOperationException("Nejste přihlášen.");

            var uc = new Datona.Web.Code.UserContext
            {
                Login = ac.UserName,
                HesloMD5 = ac.HesloMD5,
                MacAddress = "00-0C-E3-24-5A-CC",
                language_id = "1",
                InstanceId = ac.InstanceId,
                Guid_externi_db = ac.Guid_externi_db
            };
            var inst = _gcr.Instance(uc);
            if (inst == null) throw new InvalidOperationException("Nelze získat GCR instanci.");

            return inst.GetLoginentityId();
        }

        private string ClientIp() => HttpContext?.Connection?.RemoteIpAddress?.ToString() ?? "";
        private string UserAgent() => Request?.Headers["User-Agent"].ToString() ?? "";

        [HttpPost("/TwoFA/StartJson")]
        [ValidateAntiForgeryToken]
        public IActionResult StartJson()
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();

                if (_store.HasAnyActiveMethodAsync(userId).GetAwaiter().GetResult())
                    return Json(new { ok = false, err = "Už máte aktivní 2FA." });

                var secret = _totp.GenerateSecret();
                var issuer = _opts.Issuer;
                var label = $"user:{userId}";
                var period = 30;
                var digits = 6;

                var protectedSecret = _protector.Protect(Encoding.UTF8.GetBytes(secret));

                var metaJson = JsonSerializer.Serialize(new
                {
                    issuer,
                    label,
                    period,
                    digits,
                    secret_p = protectedSecret
                });

                var methodId = _store
                    .CreatePendingTotpAsync(userId, metaJson)
                    .GetAwaiter().GetResult();

                var otpUri = _totp.BuildOtpAuthUri(issuer, label, secret, digits, period);

                _store.InsertAuditAsync(userId, "mfa.start", ClientIp(), UserAgent(), new { methodId })
                      .GetAwaiter().GetResult();

                return Json(new { ok = true, otpAuthUri = otpUri, manualKey = _totp.FormatManualKey(secret) });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA StartJson error");
                return Json(new { ok = false, err = ex.Message });
            }
        }

        [HttpPost("/TwoFA/VerifyTotpJson")]
        [ValidateAntiForgeryToken]
        public IActionResult VerifyTotpJson(string code)
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();

                var method = _store.GetLatestPendingTotpAsync(userId).GetAwaiter().GetResult();
                if (method == null)
                    return Json(new { ok = false, err = "Metoda neexistuje." });

                var json = JsonDocument.Parse(method.MetaJson).RootElement;
                var protectedSecret = json.GetProperty("secret_p").GetString() ?? "";
                var secret = Encoding.UTF8.GetString(
                    _protector.Unprotect(protectedSecret)
                );

                if (!_totp.ValidateCode(secret, code))
                {
                    _store.InsertAuditAsync(userId, "mfa.verify_totp_fail", ClientIp(), UserAgent(), new { method.Id })
                          .GetAwaiter().GetResult();
                    return Json(new { ok = false, err = "Kód nesouhlasí." });
                }

                _store.InsertAuditAsync(userId, "mfa.verify_totp_ok", ClientIp(), UserAgent(), new { method.Id })
                      .GetAwaiter().GetResult();

                // generate backups
                _store.RemoveUnusedBackupCodesAsync(userId).GetAwaiter().GetResult();
                var codes = _backup.GenerateBatch();
                var plainCodes = codes.plain;
                var hashed = codes.hashed;
                _store.InsertBackupCodesAsync(userId, hashed).GetAwaiter().GetResult(); 

                _store.InsertAuditAsync(userId, "mfa.backups_generated", ClientIp(), UserAgent(), new { method.Id, count = plainCodes.Count })
                      .GetAwaiter().GetResult();

                return Json(new { ok = true, codes = plainCodes });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA VerifyTotpJson error");
                return Json(new { ok = false, err = ex.Message });
            }
        }

        [HttpPost("/TwoFA/VerifyBackupJson")]
        [ValidateAntiForgeryToken]
        public IActionResult VerifyBackupJson(string code)
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();

                var all = _store.GetUnusedBackupCodesAsync(userId).GetAwaiter().GetResult();
                var ok = all.Any(x => _backup.Verify(code, x.CodeHash));
                if (!ok)
                {
                    _store.InsertAuditAsync(userId, "mfa.verify_backup_fail", ClientIp(), UserAgent(), null)
                          .GetAwaiter().GetResult();
                    return Json(new { ok = false, err = "Neplatný kód." });
                }

                _store.ActivateMethodAsync(all.First().UserId).GetAwaiter().GetResult();
                _store.InsertAuditAsync(userId, "mfa.activated", ClientIp(), UserAgent(), null)
                      .GetAwaiter().GetResult();

                return Json(new { ok = true });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA VerifyBackupJson error");
                return Json(new { ok = false, err = ex.Message });
            }
        }

        // Controllers/DvoufaktorController.cs (výřez)
        [ValidateAntiForgeryToken]
        [HttpPost]
        public IActionResult LoginVerifyJson(string code)
        {
            try
            {
                var s = HttpContext.Session.GetString("MFA_PENDING_LOGIN");
                if (string.IsNullOrWhiteSpace(s))
                    return Json(new { ok = false, err = "Sezení vypršelo, zkuste se přihlásit znovu." });

                // rozbalit pending
                dynamic pending = Newtonsoft.Json.JsonConvert.DeserializeObject(s);
                if (pending == null || DateTime.UtcNow > (DateTime)pending.ExpiresUtc)
                {
                    HttpContext.Session.Remove("MFA_PENDING_LOGIN");
                    return Json(new { ok = false, err = "Sezení vypršelo, zkuste se přihlásit znovu." });
                }

                long loginentityId = (long)pending.loginentityId;
                // 1) zkus TOTP
                var method = _store.GetActiveTotpAsync(loginentityId).Result;
                bool ok = false;
                if (method != null)
                {
                    var meta = _totp.ParseMetaPayload(Encoding.UTF8.GetBytes(method.MetaJson));
                    ok = _totp.ValidateCode(meta.secret, code);
                }

                // 2) pokud TOTP neprojde, zkus záložní kód
                if (!ok)
                {
                    var codes = _store.GetUnusedBackupCodesAsync(loginentityId).Result;
                    var match = codes.FirstOrDefault(c => _backup.Verify(code, c.CodeHash));
                    if (match != null)
                    {
                        // Tady jsme v LOGINu, takže jej normálně označíme jako použitý:
                        _store.MarkBackupCodeUsedAsync(match.Id, DateTime.Now).Wait();
                        ok = true;
                    }
                }

                if (!ok)
                    return Json(new { ok = false, err = "Neplatný kód. Zkuste znovu." });

                // 3) úspěch → vytvoř .ASPXAUTH podle tvého původního flow
                HttpContext.Session.Remove("MFA_PENDING_LOGIN");

                string macAddress = "00-0C-E3-24-5A-CC"; // jak používáš v HomeControlleru
                var expiresInMinutes = 240;
                string ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";

                // GCR Instance se stejnými údaji jako při hesle:
                var gcrInstance = _gcr.Instance(new UserContext
                {
                    Login = (string)pending.Login,
                    HesloMD5 = (string)pending.HesloMD5,
                    InstanceId = (long)pending.InstanceId,
                    language_id = "1",
                    Guid_externi_db = (string)pending.Guid_externi_db
                });

                // ticket + cookie
                var ticket = AuthCookie.GetCookieTicket(
                    (string)pending.Login, (string)pending.HesloMD5, macAddress,
                    ((long)pending.loginentityId).ToString(), expiresInMinutes, (long)pending.InstanceId);

                var aspxAuth = AuthCookie.Encrypt(ticket);

                if (gcrInstance.vytvor_online_session(aspxAuth, (long)pending.loginentityId, ticket.ExpiresUtc, expiresInMinutes, ipAddress, null))
                {
                    Response.Cookies.Append(".ASPXAUTH", aspxAuth, new CookieOptions()
                    {
                        Expires = ticket.ExpiresUtc,
                        Path = ticket.CookiePath
                    });
                    var redirect = (string)pending.ReturnUrl;
                    return Json(new { ok = true, redirect = string.IsNullOrWhiteSpace(redirect) ? "/" : redirect });
                }
                else
                {
                    return Json(new { ok = false, err = "Chyba při založení session." });
                }
            }
            catch (Exception ex)
            {
                return Json(new { ok = false, err = ex.Message });
            }
        }
    }
}
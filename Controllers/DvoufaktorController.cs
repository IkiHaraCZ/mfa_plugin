using Datona.MobilniCisnik.Server;
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
        private readonly GcrHelper _gcr;
        private readonly ILogger<DvoufaktorController> _log;

        public DvoufaktorController(
            IMfaStore store,
            ITotpService totp,
            ISecretProtector protector,
            IBackupCodeService backup,
            GcrHelper gcr,
            ILogger<DvoufaktorController> log)
        {
            _store = store;
            _totp = totp;
            _protector = protector;
            _backup = backup;
            _gcr = gcr;
            _log = log;
        }

        private AuthenticationClaim GetAcOrThrow()
        {
            var aspx = Request.Cookies[".ASPXAUTH"];
            var ac = !string.IsNullOrEmpty(aspx)
                ? AuthCookie.AuthenticationClaim(aspx)
                : null;
            if (ac == null) throw new InvalidOperationException("Nejste přihlášen.");

            return ac;
        }

        public string Issuer { get; set; } = "PiCCOLO";

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult StartJson()
        {
            try
            {
                var ac = GetAcOrThrow();

                if (_store.HasAnyActiveMethodAsync(ac.LoginentityId).GetAwaiter().GetResult())
                    return Json(new { ok = false, err = "Už máte aktivní 2FA." });

                var secret = _totp.GenerateSecret();
                var issuer = Issuer;
                var label = $"user:{ac.UserName}";
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
                    .CreatePendingTotpAsync(ac.LoginentityId, metaJson)
                    .GetAwaiter().GetResult();

                // ULOŽ DO SESSION
                HttpContext.Session.SetString("MFA.PENDING_ID", methodId.ToString());

                var otpUri = _totp.BuildOtpAuthUri(issuer, label, secret, digits, period);

                return Json(new { ok = true, otpAuthUri = otpUri, manualKey = _totp.FormatManualKey(secret) });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA StartJson error");
                return Json(new { ok = false, err = ex.Message });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult VerifyTotpJson(string code)
        {
            try
            {
                var userId = GetAcOrThrow().LoginentityId;

                var method = _store.GetLatestPendingTotpAsync(userId).GetAwaiter().GetResult();
                if (method == null)
                    return Json(new { ok = false, err = "Metoda neexistuje." });

                var json = JsonDocument.Parse(method.MetaJson).RootElement;
                var protectedSecret = json.GetProperty("secret_p").GetString() ?? ""; //TODO zatím vyřadit šifrování, nastavíme prefix
                var secret = Encoding.UTF8.GetString(
                    _protector.Unprotect(protectedSecret)
                );

                if (!_totp.ValidateCode(secret, code))
                {
                    return Json(new { ok = false, err = "Kód nesouhlasí." });
                }

                // generate backups
                _store.RemoveUnusedBackupCodesAsync(userId).GetAwaiter().GetResult();
                var codes = _backup.GenerateBatch();
                var plainCodes = codes.plain;
                var hashed = codes.hashed;
                _store.InsertBackupCodesAsync(userId, hashed).GetAwaiter().GetResult(); 

                return Json(new { ok = true, codes = plainCodes });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA VerifyTotpJson error");
                return Json(new { ok = false, err = ex.Message });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult VerifyBackupJson(string code)
        {
            try
            {
                var userId = GetAcOrThrow().LoginentityId;

                var all = _store.GetUnusedBackupCodesAsync(userId).GetAwaiter().GetResult();
                var ok = all.Any(x => _backup.Verify(code, x.CodeHash));
                if (!ok)
                {
                    return Json(new { ok = false, err = "Neplatný kód." });
                }

                var s = HttpContext.Session.GetString("MFA.PENDING_ID");
                if (!long.TryParse(s, out var pendingMethodId) || pendingMethodId <= 0)
                    return Json(new { ok = false, err = "Vypršel kontext nastavení (pendingId)." });


                _store.ActivateMethodAsync(pendingMethodId).GetAwaiter().GetResult();
                HttpContext.Session.Remove("MFA.PENDING_ID");    // úklid

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
                    var meta = _totp.ParseMeta(method.MetaJson);
                    ok = _totp.ValidateCode(Encoding.UTF8.GetString(_protector.Unprotect(meta.secret)), code);
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

                // 3) úspěch → vytvoř .ASPXAUTH
                HttpContext.Session.Remove("MFA_PENDING_LOGIN");

                string macAddress = "00-0C-E3-24-5A-CC";
                var expiresInMinutes = 240;
                string ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";

                // GCR Instance
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

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult LoginAbortJson()
        {
            try
            {
                // Zahoď rozpracovaný login/MFA stav:
                HttpContext.Session?.Remove("MFA_PendingMethodId");
                HttpContext.Session?.Remove("MFA_LoginNonce");
                Response.Cookies.Delete(".ASPXAUTH");

                return Json(new { ok = true });
            }
            catch
            {
                return BadRequest(new { ok = false });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult VypnoutJson()
        {
            try
            {
                var userId = GetAcOrThrow().LoginentityId;

                // zruš aktivní metody + smaž záložní kódy (sync via .Result)
                _store.RevokeAllMethodsAsync(userId).GetAwaiter().GetResult();
                _store.DeleteAllBackupCodesAsync(userId).GetAwaiter().GetResult();

                return Json(new { ok = true });
            }
            catch (Exception ex)
            {
                // zaloguj ex.ToString()
                return Json(new { ok = false, err = "Nepodařilo se vypnout 2FA." });
            }
        }
    }
}
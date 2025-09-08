using Datona.MobilniCisnik.Server;
using Datona.Web.Code;
using Datona.Web.Code.Security;
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
    }
}

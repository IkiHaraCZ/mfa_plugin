using System;
using System.Linq;
using System.Text.Json;
using Datona.MobilniCisnik.Server;
using Datona.Web.Code;
using Datona.Web.Code.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Datona.Web.Controllers
{
    [Route("TwoFA")]
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

        // --- helpers ---
        private long GetCurrentUserIdOrThrow()
        {
            var aspx = Request.Cookies[".ASPXAUTH"];
            var ac = !string.IsNullOrEmpty(aspx) ? AuthCookie.AuthenticationClaim(aspx) : null;
            if (ac == null) throw new InvalidOperationException("Nejste přihlášen.");

            var inst = _gcr.Instance(new UserContext
            {
                Login = ac.UserName,
                HesloMD5 = ac.HesloMD5,
                MacAddress = "00-0C-E3-24-5A-CC",
                language_id = "1",
                InstanceId = ac.InstanceId,
                Guid_externi_db = ac.Guid_externi_db
            });
            if (inst == null) throw new InvalidOperationException("Nelze získat GCR instanci.");

            return inst.GetLoginentityId();
        }

        private string ClientIp() => HttpContext?.Connection?.RemoteIpAddress?.ToString() ?? "";
        private string UserAgent() => Request?.Headers["User-Agent"].ToString() ?? "";

        // KROK 1: start – vytvoří pending TOTP, vrátí QR + „manual key“ (read-only)
        [HttpPost("start")]
        public IActionResult Start()
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();

                var hasActive = _store.HasAnyActiveMethodAsync(userId).GetAwaiter().GetResult();
                if (hasActive)
                    return Json(new { ok = false, error = "Už máte aktivní 2FA." });

                var secret = _totp.GenerateSecret();
                var label = $"{_opts.Issuer}:{userId}";
                var metaJson = _totp.BuildMetaPayload(secret, _opts.Issuer, label, period: 30, digits: 6);

                var methodId = _store.CreatePendingTotpAsync(userId, _protector.Protect(metaJson)).GetAwaiter().GetResult();

                var otpAuthUri = _totp.BuildOtpAuthUri(_opts.Issuer, label, secret, digits: 6, period: 30);
                var qrUrl = Url.Content($"/qr/otp?data={Uri.EscapeDataString(otpAuthUri)}&size=240");
                var manual = _totp.FormatManualKey(secret);

                _store.InsertAuditAsync(userId, "mfa.start", ClientIp(), UserAgent(), new { methodId })
                      .GetAwaiter().GetResult();

                return Json(new { ok = true, methodId, qrUrl, manualKey = manual });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA/Start error");
                return Json(new { ok = false, error = ex.Message });
            }
        }

        // KROK 1b: ověř TOTP proti pending metodě
        [HttpPost("verify-totp")]
        public IActionResult VerifyTotp([FromForm] long methodId, [FromForm] string code)
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();
                var method = _store.GetLatestPendingTotpAsync(userId).GetAwaiter().GetResult();
                if (method == null || method.Id != methodId)
                    return Json(new { ok = false, error = "Metoda nenalezena nebo už není v nastavení." });

                var metaProtected = method.MetaJson;
                var metaJson = _protector.Unprotect(metaProtected);
                var (secret, issuer, label, period, digits) = _totp.ParseMetaPayload(metaJson);

                if (!_totp.ValidateCode(secret, code))
                {
                    _store.InsertAuditAsync(userId, "mfa.verify_totp_fail", ClientIp(), UserAgent(), new { methodId })
                          .GetAwaiter().GetResult();
                    return Json(new { ok = false, error = "Kód nesouhlasí." });
                }

                _store.InsertAuditAsync(userId, "mfa.verify_totp_ok", ClientIp(), UserAgent(), new { methodId })
                      .GetAwaiter().GetResult();

                return Json(new { ok = true });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA/VerifyTotp error");
                return Json(new { ok = false, error = ex.Message });
            }
        }

        // KROK 2: vygeneruj záložní kódy (uloží se jen hash; plaintext vracíme teď)
        [HttpPost("generate-backups")]
        public IActionResult GenerateBackups([FromForm] long methodId)
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();

                _store.RemoveUnusedBackupCodesAsync(userId).GetAwaiter().GetResult();
                var codes = _backup.GenerateBatch();
                var plain = codes.plain;
                var hashed = codes.hashed;
                _store.InsertBackupCodesAsync(userId, hashed).GetAwaiter().GetResult();

                _store.InsertAuditAsync(userId, "mfa.backups_generated", ClientIp(), UserAgent(), new { methodId, count = plain.Count })
                      .GetAwaiter().GetResult();

                return Json(new { ok = true, codes = plain });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA/GenerateBackups error");
                return Json(new { ok = false, error = ex.Message });
            }
        }

        // KROK 3: potvrď, že si je uživatel uložil
        [HttpPost("confirm-saved")]
        public IActionResult ConfirmSaved([FromForm] long methodId)
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();
                _store.InsertAuditAsync(userId, "mfa.backups_confirmed", ClientIp(), UserAgent(), new { methodId })
                      .GetAwaiter().GetResult();
                return Json(new { ok = true });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA/ConfirmSaved error");
                return Json(new { ok = false, error = ex.Message });
            }
        }

        // KROK 3b: ověř jeden záložní kód (NEspotřebovat – jen ověřit proti hashům)
        [HttpPost("verify-backup")]
        public IActionResult VerifyBackup([FromForm] long methodId, [FromForm] string code)
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();
                var all = _store.GetUnusedBackupCodesAsync(userId).GetAwaiter().GetResult();
                var ok = all.Any(x => _backup.Verify(code, x.CodeHash));
                if (!ok)
                {
                    _store.InsertAuditAsync(userId, "mfa.verify_backup_fail", ClientIp(), UserAgent(), new { methodId })
                          .GetAwaiter().GetResult();
                    return Json(new { ok = false, error = "Zadaný záložní kód není z této dávky." });
                }

                _store.InsertAuditAsync(userId, "mfa.verify_backup_ok", ClientIp(), UserAgent(), new { methodId })
                      .GetAwaiter().GetResult();
                return Json(new { ok = true });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA/VerifyBackup error");
                return Json(new { ok = false, error = ex.Message });
            }
        }

        // KROK 4: aktivace metody
        [HttpPost("activate")]
        public IActionResult Activate([FromForm] long methodId)
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();
                _store.ActivateMethodAsync(methodId).GetAwaiter().GetResult();
                _store.InsertAuditAsync(userId, "mfa.activated", ClientIp(), UserAgent(), new { methodId })
                      .GetAwaiter().GetResult();
                return Json(new { ok = true });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA/Activate error");
                return Json(new { ok = false, error = ex.Message });
            }
        }
    }
}

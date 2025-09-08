using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
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
        private readonly MfaPozadavkyVolby _opts;
        private readonly GcrHelper _gcr;
        private readonly ILogger<DvoufaktorController> _log;

        public DvoufaktorController(
            IMfaStore store,
            ITotpService totp,
            ISecretProtector protector,
            IBackupCodeService backup,
            MfaPozadavkyVolby opts,
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

        // Pomocně: aktuální loginentity_id
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

        // STEP 1: zahájit nastavení – vytvoří PENDING TOTP metodu, vrátí QR a „manual“ string (jen k opsání, ne vlastní secret)
        [HttpPost("start")]
        public async Task<IActionResult> Start()
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();

                // Pokud už má aktivní metodu, vrať informaci (tlačítko v UI se má stejně zobrazovat jen pokud není 2FA nastaveno)
                if (await _store.HasAnyActiveMethodAsync(userId))
                    return Json(new { ok = false, error = "Už máte aktivní 2FA." });

                // vygenerovat secret a metadata
                var secret = _totp.GenerateSecret();
                var label = $"{_opts.Issuer}:{userId}";
                var metaJson = _totp.BuildMetaJson(secret, _opts.Issuer, label, period: 30, digits: 6);

                // uložit pending metodu
                var methodId = await _store.CreatePendingTotpAsync(userId, _protector.Protect(metaJson));

                // QR/URI
                var otpAuthUri = _totp.BuildOtpAuthUri(_opts.Issuer, label, secret, digits: 6, period: 30);
                // QR controller už v projektu máš: /qr/otp?data=...&size=240
                var qrUrl = Url.Content($"/qr/otp?data={Uri.EscapeDataString(otpAuthUri)}&size=240");
                var manual = _totp.FormatManualKey(secret);

                await _store.InsertAuditAsync(userId, "mfa.start", ClientIp(), UserAgent(), new { methodId });

                return Json(new
                {
                    ok = true,
                    methodId,
                    qrUrl,
                    manualKey = manual
                });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA/Start error");
                return Json(new { ok = false, error = ex.Message });
            }
        }

        // STEP 1b: ověř TOTP kód proti pending metodě
        [HttpPost("verify-totp")]
        public async Task<IActionResult> VerifyTotp([FromForm] long methodId, [FromForm] string code)
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();
                var method = await _store.GetLatestPendingTotpAsync(userId);
                if (method == null || method.Id != methodId)
                    return Json(new { ok = false, error = "Metoda nenalezena nebo už není v nastavení." });

                // rozbal meta
                var metaProtected = method.MetaJson;
                var metaJson = _protector.Unprotect(metaProtected);
                var (secret, issuer, label, period, digits) = _totp.ParseMeta(metaJson);

                if (!_totp.ValidateCode(secret, code))
                {
                    await _store.InsertAuditAsync(userId, "mfa.verify_totp_fail", ClientIp(), UserAgent(), new { methodId });
                    return Json(new { ok = false, error = "Kód nesouhlasí." });
                }

                await _store.InsertAuditAsync(userId, "mfa.verify_totp_ok", ClientIp(), UserAgent(), new { methodId });
                return Json(new { ok = true });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA/VerifyTotp error");
                return Json(new { ok = false, error = ex.Message });
            }
        }

        // STEP 2: vygeneruj batch záložních kódů (uloží se jen hash, plaintext pošleme jednou)
        [HttpPost("generate-backups")]
        public async Task<IActionResult> GenerateBackups([FromForm] long methodId)
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();

                // čistka nepoužitých předchozích batchů
                await _store.RemoveUnusedBackupCodesAsync(userId);

                var plain = _backup.GeneratePlaintextCodes(_opts.BackupCodesCount).ToList();
                var hashed = plain.Select(_backup.Hash).ToList();
                await _store.InsertBackupCodesAsync(userId, hashed);

                await _store.InsertAuditAsync(userId, "mfa.backups_generated", ClientIp(), UserAgent(), new { methodId, count = plain.Count });

                return Json(new { ok = true, codes = plain });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA/GenerateBackups error");
                return Json(new { ok = false, error = ex.Message });
            }
        }

        // STEP 3: potvrď, že si je uživatel uložil (jen audit + server nic nemaže)
        [HttpPost("confirm-saved")]
        public async Task<IActionResult> ConfirmSaved([FromForm] long methodId)
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();
                await _store.InsertAuditAsync(userId, "mfa.backups_confirmed", ClientIp(), UserAgent(), new { methodId });
                return Json(new { ok = true });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA/ConfirmSaved error");
                return Json(new { ok = false, error = ex.Message });
            }
        }

        // STEP 3b: ověř jeden záložní kód (NEspotřebovat! pouze ověřit — musí projít hashovaným porovnáním)
        [HttpPost("verify-backup")]
        public async Task<IActionResult> VerifyBackup([FromForm] long methodId, [FromForm] string code)
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();
                var all = await _store.GetUnusedBackupCodesAsync(userId);
                var ok = all.Any(x => _backup.Verify(code, x.CodeHash));
                if (!ok)
                {
                    await _store.InsertAuditAsync(userId, "mfa.verify_backup_fail", ClientIp(), UserAgent(), new { methodId });
                    return Json(new { ok = false, error = "Zadaný záložní kód není z této dávky." });
                }

                await _store.InsertAuditAsync(userId, "mfa.verify_backup_ok", ClientIp(), UserAgent(), new { methodId });
                return Json(new { ok = true });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "TwoFA/VerifyBackup error");
                return Json(new { ok = false, error = ex.Message });
            }
        }

        // STEP 4: aktivuj metodu (Pending -> Active)
        [HttpPost("activate")]
        public async Task<IActionResult> Activate([FromForm] long methodId)
        {
            try
            {
                var userId = GetCurrentUserIdOrThrow();
                await _store.ActivateMethodAsync(methodId);
                await _store.InsertAuditAsync(userId, "mfa.activated", ClientIp(), UserAgent(), new { methodId });
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
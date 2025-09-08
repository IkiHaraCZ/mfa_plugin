using System;
using System.Linq;
using System.Threading.Tasks;
using Datona.Web.Code;
using Datona.Web.Code.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Datona.Web.Controllers
{
    [Route("TwoFA")]
    public class DvoufaktorController : Controller
    {
        private const string LoginSessionUserKey = "MFA_Login_UserId";

        private readonly IMfaStore _store;
        private readonly ITotpService _totp;
        private readonly ISecretProtector _protector;
        private readonly IBackupCodeService _backup;
        private readonly MfaPozadavkyVolby _rules;
        private readonly GcrHelper _gcr;

        public DvoufaktorController(
            IMfaStore store,
            ITotpService totp,
            ISecretProtector protector,
            IBackupCodeService backup,
            MfaPozadavkyVolby rules,
            GcrHelper gcr)
        {
            _store = store;
            _totp = totp;
            _protector = protector;
            _backup = backup;
            _rules = rules;
            _gcr = gcr;
        }

        // ========= Pomocné získání uživatele =========

        private long GetCurrentUserIdOrZero()
        {
            // V tvém projektu je k dispozici přes .ASPXAUTH -> GCR instance
            try
            {
                return _gcr.PublicInstance()?.GetLoginentityId() ?? 0;
            }
            catch
            {
                return 0;
            }
        }

        private long GetPendingLoginUserIdOrZero()
        {
            var s = HttpContext.Session.GetString(LoginSessionUserKey);
            return long.TryParse(s, out var id) ? id : 0;
        }

        // ========= A) SETUP WIZARD (modál v _Layout) =========

        /// <summary>
        /// Připraví pending TOTP (pokud není), vrátí otpauth URI + manuální kód.
        /// </summary>
        [HttpPost("StartJson")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> StartJson()
        {
            var uid = GetCurrentUserIdOrZero();
            if (uid <= 0) return Json(new { ok = false, err = "Uživatel není přihlášen." });

            var pending = await _store.GetLatestPendingTotpAsync(uid);
            if (pending == null)
            {
                // vygeneruj secret a ulož meta_json do pending záznamu
                var secret = _totp.GenerateSecret();
                var issuer = string.IsNullOrWhiteSpace(_rules.Issuer) ? "PiCCOLO" : _rules.Issuer;
                var label = $"{issuer}:{uid}";
                var meta = _totp.BuildMetaJson(secret, issuer, label, 30, 6); // přizpůsob své implementaci
                await _store.CreatePendingTotpAsync(uid, meta);
                pending = await _store.GetLatestPendingTotpAsync(uid);
            }

            var (secretRaw, issuer2, label2, period, digits) = _totp.ParseMeta(pending!.MetaJson);
            var otpAuthUri = _totp.BuildOtpAuthUri(issuer2, label2, secretRaw, digits, period);
            var manualKey = _totp.FormatManualKey(secretRaw);

            return Json(new { ok = true, otpAuthUri, manualKey });
        }

        /// <summary>
        /// Ověří TOTP kód; při úspěchu vygeneruje záložní kódy (hash uloží do DB, plaintext vrátí).
        /// </summary>
        [HttpPost("VerifyTotpJson")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyTotpJson([FromForm] string code)
        {
            var uid = GetCurrentUserIdOrZero();
            if (uid <= 0) return Json(new { ok = false, err = "Uživatel není přihlášen." });

            var pending = await _store.GetLatestPendingTotpAsync(uid);
            if (pending == null) return Json(new { ok = false, err = "Nenalezeno čekající nastavení." });

            var (secretRaw, _, _, _, _) = _totp.ParseMeta(pending.MetaJson);
            if (!_totp.ValidateCode(secretRaw, code?.Trim()))
                return Json(new { ok = false, err = "Nesprávný kód. Zkuste to znovu." });

            // volitelně: smazat staré nepoužité záložní kódy
            await _store.RemoveUnusedBackupCodesAsync(uid);

            var count = _rules.BackupCodesCount > 0 ? _rules.BackupCodesCount : 10;
            var plain = _backup.GeneratePlaintextCodes(count).ToArray();
            foreach (var c in plain)
                await _store.InsertBackupCodesAsync(uid, new[] { _backup.Hash(c) });

            return Json(new { ok = true, codes = plain });
        }

        /// <summary>
        /// Ověří jeden záložní kód (bez spotřeby) a aktivuje pending TOTP.
        /// </summary>
        [HttpPost("VerifyBackupJson")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyBackupJson([FromForm] string code)
        {
            var uid = GetCurrentUserIdOrZero();
            if (uid <= 0) return Json(new { ok = false, err = "Uživatel není přihlášen." });

            var unused = await _store.GetUnusedBackupCodesAsync(uid);
            var match = unused.FirstOrDefault(b => _backup.Verify(code?.Trim() ?? "", b.CodeHash));
            if (match == null)
                return Json(new { ok = false, err = "Zadaný kód není platný." });

            // Neznačíme jako "použitý" – pouze ověřujeme, že kódy má uložené.

            var pending = await _store.GetLatestPendingTotpAsync(uid);
            if (pending != null)
                await _store.ActivateMethodAsync(pending.Id);

            return Json(new { ok = true });
        }

        /// <summary>
        /// Zda má aktuální uživatel nějakou aktivní 2FA metodu.
        /// </summary>
        [HttpGet("StatusJson")]
        public async Task<IActionResult> StatusJson()
        {
            var uid = GetCurrentUserIdOrZero();
            if (uid <= 0) return Json(new { ok = false, hasActive = false });
            var has = await _store.HasAnyActiveMethodAsync(uid);
            return Json(new { ok = true, hasActive = has });
        }

        /// <summary>
        /// Vypnutí 2FA: zruší metody a smaže záložní kódy (volitelné do budoucna).
        /// </summary>
        [HttpPost("RevokeJson")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RevokeJson()
        {
            var uid = GetCurrentUserIdOrZero();
            if (uid <= 0) return Json(new { ok = false, err = "Uživatel není přihlášen." });

            await _store.RevokeAllMethodsAsync(uid);
            await _store.DeleteAllBackupCodesAsync(uid);

            return Json(new { ok = true });
        }

        // ========= B) 2FA PŘI PŘIHLÁŠENÍ (login flow) =========
        // Tohle nespouští wizard – to je separátní (typicky jiný modál na login stránce).

        /// <summary>
        /// Uloží userId do session a vrátí, zda je 2FA povinné (tj. má aktivní metodu).
        /// Volá se po úspěšné kontrole hesla, ale před vydáním .ASPXAUTH.
        /// </summary>
        [HttpPost("Login/BeginJson")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginBeginJson([FromForm] long userId)
        {
            if (userId <= 0) return Json(new { ok = false, err = "Neplatný uživatel." });

            HttpContext.Session.SetString(LoginSessionUserKey, userId.ToString());

            var required = await _store.HasAnyActiveMethodAsync(userId);
            return Json(new { ok = true, require2fa = required });
        }

        /// <summary>
        /// Ověří TOTP kód pro pending-login uživatele v session.
        /// </summary>
        [HttpPost("Login/VerifyTotpJson")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginVerifyTotpJson([FromForm] string code)
        {
            var uid = GetPendingLoginUserIdOrZero();
            if (uid <= 0) return Json(new { ok = false, err = "Session 2FA nenalezena." });

            var active = await _store.GetActiveTotpAsync(uid);
            if (active == null) return Json(new { ok = false, err = "2FA není aktivní." });

            var (secretRaw, _, _, _, _) = _totp.ParseMeta(active.MetaJson);
            if (!_totp.ValidateCode(secretRaw, code?.Trim()))
                return Json(new { ok = false, err = "Nesprávný kód." });

            await _store.SetMethodLastUsedAsync(active.Id, DateTime.Now);
            return Json(new { ok = true });
        }

        /// <summary>
        /// Ověří záložní kód pro pending-login uživatele v session (kód se spotřebuje).
        /// </summary>
        [HttpPost("Login/VerifyBackupJson")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginVerifyBackupJson([FromForm] string code)
        {
            var uid = GetPendingLoginUserIdOrZero();
            if (uid <= 0) return Json(new { ok = false, err = "Session 2FA nenalezena." });

            var unused = await _store.GetUnusedBackupCodesAsync(uid);
            var match = unused.FirstOrDefault(b => _backup.Verify(code?.Trim() ?? "", b.CodeHash));
            if (match == null)
                return Json(new { ok = false, err = "Neplatný kód." });

            await _store.MarkBackupCodeUsedAsync(match.Id, DateTime.Now);
            return Json(new { ok = true });
        }
    }
}
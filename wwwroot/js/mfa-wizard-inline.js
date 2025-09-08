// wwwroot/js/mfa-wizard-inline.js
// 2FA wizard – vanilla JS + Bootstrap modal (s jQuery i bez).
(function (global) {
    "use strict";

    // === helpers ===
    function byId(id) { return document.getElementById(id); }
    function setErr(id, msg) {
        var e = byId(id);
        if (!e) return;
        if (!msg) { e.style.display = 'none'; e.innerText = ''; return; }
        e.innerText = msg;
        e.style.display = '';
    }
    function showStep(id) {
        document.querySelectorAll('.mfaW-step').forEach(x => x.style.display = 'none');
        var el = byId(id);
        if (el) el.style.display = 'block';
    }
    function getCsrf() {
        const i = document.querySelector('input[name="__RequestVerificationToken"]');
        return i ? i.value : null;
    }
    async function post(url, data) {
        const form = new URLSearchParams();
        const token = getCsrf();
        if (token) form.append('__RequestVerificationToken', token);
        if (data) Object.keys(data).forEach(k => form.append(k, data[k] ?? ''));
        const res = await fetch(url, { method: 'POST', headers: { 'Accept': 'application/json' }, body: form });
        return await res.json();
    }

    // Bootstrap/jQuery pøítomnost
    function hasJqModal() {
        return !!(global.jQuery && typeof global.jQuery.fn.modal === 'function');
    }

    // Fallback modal open/close (bez jQuery)
    function openModalFallback() {
        const modal = byId('mfaWizardModal');
        if (!modal) return;
        modal.style.display = 'block';
        modal.classList.add('show');
        document.body.classList.add('modal-open');

        // pøidej backdrop pokud chybí
        if (!byId('mfaW-backdrop')) {
            const bd = document.createElement('div');
            bd.className = 'modal-backdrop fade show';
            bd.id = 'mfaW-backdrop';
            document.body.appendChild(bd);
        }
    }
    function closeModalFallback() {
        const modal = byId('mfaWizardModal');
        if (modal) {
            modal.classList.remove('show');
            modal.style.display = 'none';
        }
        document.body.classList.remove('modal-open');
        const bd = byId('mfaW-backdrop');
        if (bd) bd.remove();
    }

    const MFAW = {
        open: async function () {
            // otevøít modal (jQuery/BS pokud je, jinak fallback)
            if (hasJqModal()) {
                global.jQuery('#mfaWizardModal').modal('show');
            } else {
                openModalFallback();
            }

            // reset stavu
            ['mfaW-err1', 'mfaW-err2', 'mfaW-err3'].forEach(id => setErr(id));
            if (byId('mfaW-totp')) byId('mfaW-totp').value = '';
            if (byId('mfaW-backup')) byId('mfaW-backup').value = '';
            if (byId('mfaW-codes')) byId('mfaW-codes').innerHTML = '';
            if (byId('mfaW-saved')) byId('mfaW-saved').checked = false;
            if (byId('mfaW-qr')) byId('mfaW-qr').src = '';
            if (byId('mfaW-manual')) byId('mfaW-manual').innerText = '';

            // init
            showStep('mfaW-step1');
            try {
                const r = await post('/TwoFA/StartJson');
                if (r.ok) {
                    if (byId('mfaW-qr')) byId('mfaW-qr').src = '/qr/otp?data=' + encodeURIComponent(r.otpAuthUri) + '&size=240';
                    if (byId('mfaW-manual')) byId('mfaW-manual').innerText = r.manualKey || '';
                    setTimeout(() => { if (byId('mfaW-totp')) byId('mfaW-totp').focus(); }, 80);
                } else {
                    setErr('mfaW-err1', r.err || 'Chyba inicializace.');
                }
            } catch {
                setErr('mfaW-err1', 'Chyba sítì.');
            }
        },

        verifyTotp: async function () {
            const code = (byId('mfaW-totp')?.value || '').trim();
            setErr('mfaW-err1');
            if (!code) { setErr('mfaW-err1', 'Zadejte kód.'); return; }

            try {
                const r = await post('/TwoFA/VerifyTotpJson', { code });
                if (r.ok) {
                    const box = byId('mfaW-codes');
                    if (box) {
                        box.innerHTML = '';
                        (r.codes || []).forEach(c => {
                            const div = document.createElement('div');
                            div.textContent = c;
                            box.appendChild(div);
                        });
                    }
                    showStep('mfaW-step2');
                } else {
                    setErr('mfaW-err1', r.err || 'Kód nesouhlasí.');
                }
            } catch {
                setErr('mfaW-err1', 'Chyba sítì.');
            }
        },

        confirmSaved: function () {
            setErr('mfaW-err2');
            const chk = byId('mfaW-saved');
            if (!chk || !chk.checked) { setErr('mfaW-err2', 'Potvrïte prosím, že jste si kódy uložili.'); return; }
            showStep('mfaW-step3');
            setTimeout(() => { if (byId('mfaW-backup')) byId('mfaW-backup').focus(); }, 80);
        },

        verifyBackup: async function () {
            const code = (byId('mfaW-backup')?.value || '').trim();
            setErr('mfaW-err3');
            if (!code) { setErr('mfaW-err3', 'Zadejte kód.'); return; }

            try {
                const r = await post('/TwoFA/VerifyBackupJson', { code });
                if (r.ok) {
                    showStep('mfaW-step4');
                } else {
                    setErr('mfaW-err3', r.err || 'Neplatný kód.');
                }
            } catch {
                setErr('mfaW-err3', 'Chyba sítì.');
            }
        },

        close: function () {
            if (hasJqModal()) {
                global.jQuery('#mfaWizardModal').modal('hide');
            } else {
                closeModalFallback();
            }
        },

        afterFinish: function () {
            // pøípadnì pøepnout UI (napø. na "Vypnout 2FA")
            // location.reload();
        }
    };

    // export
    global.MFAW = MFAW;

})(window);
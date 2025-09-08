// wwwroot/js/mfa-wizard-inline.js
// 2FA wizard – vanilla JS + Bootstrap modal.
// Oèekává existenci modal markup s id="mfaWizardModal" a krokù s class="mfaW-step" (step1..4).

(function (global) {
  "use strict";

  function $(id) { return document.getElementById(id); }

  // Anti-forgery token (v layoutu je @Html.AntiForgeryToken())
  function getCsrf() {
    const i = document.querySelector('input[name="__RequestVerificationToken"]');
    return i ? i.value : null;
  }

  function showStep(id) {
    document.querySelectorAll('.mfaW-step').forEach(x => x.style.display = 'none');
    var el = $(id);
    if (el) el.style.display = 'block';
  }

  function setErr(id, msg) {
    var e = $(id);
    if (!e) return;
    if (!msg) { e.style.display = 'none'; e.innerText = ''; return; }
    e.innerText = msg;
    e.style.display = '';
  }

  async function post(url, data) {
    const form = new URLSearchParams();
    const token = getCsrf();
    if (token) form.append('__RequestVerificationToken', token);
    if (data) Object.keys(data).forEach(k => form.append(k, data[k] ?? ''));
    const res = await fetch(url, { method: 'POST', headers: { 'Accept': 'application/json' }, body: form });
    return await res.json();
  }

  const MFAW = {
    open: async function () {
      // otevøít modal
      if (window.$ && typeof $('#mfaWizardModal').modal === 'function') {
        $('#mfaWizardModal').modal('show');     // pokud je k dispozici jQuery + Bootstrap
      } else {
        // fallback – bez jQuery: necháme modal viditelný (pøedpoklad: už je v DOM se zobrazením pøes CSS)
        var modal = document.getElementById('mfaWizardModal');
        if (modal) modal.style.display = 'block';
      }

      // reset stavu
      ['mfaW-err1','mfaW-err2','mfaW-err3'].forEach(id => setErr(id));
      if ($('mfaW-totp')) $('mfaW-totp').value = '';
      if ($('mfaW-backup')) $('mfaW-backup').value = '';
      if ($('mfaW-codes')) $('mfaW-codes').innerHTML = '';
      if ($('mfaW-saved')) $('mfaW-saved').checked = false;
      if ($('mfaW-qr')) $('mfaW-qr').src = '';
      if ($('mfaW-manual')) $('mfaW-manual').innerText = '';

      // init (pendující metoda + QR + manuál)
      showStep('mfaW-step1');
      try {
        const r = await post('/TwoFA/StartJson');
        if (r.ok) {
          if ($('mfaW-qr')) $('mfaW-qr').src = '/qr/otp?data=' + encodeURIComponent(r.otpAuthUri) + '&size=240';
          if ($('mfaW-manual')) $('mfaW-manual').innerText = r.manualKey || '';
          setTimeout(() => { if ($('mfaW-totp')) $('mfaW-totp').focus(); }, 80);
        } else {
          setErr('mfaW-err1', r.err || 'Chyba inicializace.');
        }
      } catch {
        setErr('mfaW-err1', 'Chyba sítì.');
      }
    },

    verifyTotp: async function () {
      const code = ($('mfaW-totp')?.value || '').trim();
      setErr('mfaW-err1');
      if (!code) { setErr('mfaW-err1', 'Zadejte kód.'); return; }

      try {
        const r = await post('/TwoFA/VerifyTotpJson', { code });
        if (r.ok) {
          const box = $('mfaW-codes');
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
      const chk = $('mfaW-saved');
      if (!chk || !chk.checked) { setErr('mfaW-err2', 'Potvrïte prosím, že jste si kódy uložili.'); return; }
      showStep('mfaW-step3');
      setTimeout(() => { if ($('mfaW-backup')) $('mfaW-backup').focus(); }, 80);
    },

    verifyBackup: async function () {
      const code = ($('mfaW-backup')?.value || '').trim();
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

    afterFinish: function () {
      // pøípadnì refresh UI – zmìna tlaèítka na „Vypnout 2FA“ apod.
      // location.reload();
    }
  };

  // export
  global.MFAW = MFAW;

})(window);
// wwwroot/js/mfa-wizard.js
window.MFAW = (function () {
  let methodId = null;
  let codes = [];

  function show(stepId) {
    $('.mfaW-step').hide();
    $(stepId).show();
  }

  function setErr(id, msg) {
    const $e = $(id);
    if (!msg) { $e.hide().text(''); return; }
    $e.text(msg).show();
  }

  async function post(url, data) {
    return $.ajax({ url, type: 'POST', data });
  }

  async function open() {
    // reset UI
    setErr('#mfaW-err1'); setErr('#mfaW-err2'); setErr('#mfaW-err3');
    $('#mfaW-totp').val('');
    $('#mfaW-backup').val('');
    $('#mfaW-saved').prop('checked', false);
    $('#mfaW-qr').attr('src','');
    $('#mfaW-manual').text('•••• •••• ••••');
    methodId = null; codes = [];

    $('#mfaWizardModal').modal('show');
    show('#mfaW-step1');

    // start
    const res = await post('/TwoFA/start', {});
    if (!res.ok) { setErr('#mfaW-err1', res.error || 'Chyba inicializace.'); return; }

    methodId = res.methodId;
    $('#mfaW-qr').attr('src', res.qrUrl);
    $('#mfaW-manual').text(res.manualKey);
  }

  async function verifyTotp() {
    setErr('#mfaW-err1');
    const code = ($('#mfaW-totp').val() || '').trim();
    if (!code) { setErr('#mfaW-err1','Zadejte kód.'); return; }

    const res = await post('/TwoFA/verify-totp', { methodId, code });
    if (!res.ok) { setErr('#mfaW-err1', res.error || 'Kód nesouhlasí.'); return; }

    // vygenerovat záložní kódy
    const g = await post('/TwoFA/generate-backups', { methodId });
    if (!g.ok) { setErr('#mfaW-err1', g.error || 'Nelze vygenerovat záložní kódy.'); return; }
    codes = g.codes || [];
    $('#mfaW-codes').html(codes.map(c => `<div>${c}</div>`).join(''));
    show('#mfaW-step2');
  }

  async function confirmSaved() {
    setErr('#mfaW-err2');
    if (!$('#mfaW-saved').is(':checked')) {
      setErr('#mfaW-err2', 'Potvrïte, že jste si kódy uložil(a).'); return;
    }
    const res = await post('/TwoFA/confirm-saved', { methodId });
    if (!res.ok) { setErr('#mfaW-err2', res.error || 'Chyba potvrzení.'); return; }
    show('#mfaW-step3');
  }

  async function verifyBackup() {
    setErr('#mfaW-err3');
    const code = ($('#mfaW-backup').val() || '').trim();
    if (!code) { setErr('#mfaW-err3','Zadejte jeden ze záložních kódù.'); return; }

    const res = await post('/TwoFA/verify-backup', { methodId, code });
    if (!res.ok) { setErr('#mfaW-err3', res.error || 'Kód není z této dávky.'); return; }

    const act = await post('/TwoFA/activate', { methodId });
    if (!act.ok) { setErr('#mfaW-err3', act.error || 'Nelze aktivovat.'); return; }

    show('#mfaW-step4');
  }

  function afterFinish() {
    // pøípadnì refresh UI / badge
    location.reload();
  }

  return { open, verifyTotp, confirmSaved, verifyBackup, afterFinish };
})();
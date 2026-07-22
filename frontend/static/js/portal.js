/* Portal "Client OAuth Configuration" helper: fills in the settings for
 * whichever registered app is selected, and can fire a real /authorize
 * round trip in a new tab to sanity-check a client's redirect URI. Port of
 * the inline JS that used to live in internal/server/web.go's handlePortal. */

function fillConfig() {
  const sel = document.getElementById('appSel');
  const opt = sel.options[sel.selectedIndex];
  if (!opt.value) { document.getElementById('cfg').style.display = 'none'; return; }
  document.getElementById('c-cid').textContent = opt.value;
  document.getElementById('c-sec').textContent = opt.getAttribute('data-secret') || '(public client — no secret)';
  const uris = (opt.getAttribute('data-uris') || '').split(',');
  document.getElementById('c-redir').textContent = uris[0] || '';
  document.getElementById('cfg').style.display = 'block';
}

function testFlow() {
  const sel = document.getElementById('appSel');
  const opt = sel.options[sel.selectedIndex];
  if (!opt.value) { alert('Select an application first'); return; }
  const uris = (opt.getAttribute('data-uris') || '').split(',');
  if (!uris[0]) { alert('No redirect URI registered for this app'); return; }
  const state = Math.random().toString(36).slice(2);
  const url = '/authorize?response_type=code&client_id=' + encodeURIComponent(opt.value) +
    '&redirect_uri=' + encodeURIComponent(uris[0]) +
    '&scope=openid+profile+email&state=' + state;
  document.getElementById('flowResult').textContent = 'Opening OAuth flow in new tab…';
  window.open(url, '_blank');
}

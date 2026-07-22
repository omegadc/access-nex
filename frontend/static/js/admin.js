/* Admin console: drives /api/admin/* directly from the browser (same-origin
 * through the frontend's proxy, so the oidc_sid session cookie travels with
 * every call). Port of the inline JS that used to live in
 * internal/server/admin.go's handleAdminPage. */

const ADMIN_HEADERS = { 'Content-Type': 'application/json', 'X-Access-Nex-Admin': '1' };

function escapeHtml(t) {
  const d = document.createElement('div');
  d.textContent = t ?? '';
  return d.innerHTML;
}

async function loadUsers() {
  const res = await fetch('/api/admin/users');
  const data = await res.json();
  const t = document.getElementById('users-table');
  let rows = '';
  for (const u of data.users || []) {
    rows += `<tr><td class="td-name">${escapeHtml(u.username)}</td><td>${escapeHtml(u.email)}</td><td>${escapeHtml(u.name)}</td>` +
      `<td>${escapeHtml(u.source)}</td><td>${u.is_admin ? '<span class="badge badge-green">admin</span>' : ''}</td>` +
      `<td><button class="btn btn-danger btn-sm" onclick="deleteUser('${escapeHtml(u.username)}')">Delete</button></td></tr>`;
  }
  t.innerHTML = rows || '<tr class="empty-row"><td colspan="6">No users</td></tr>';
}

async function createUser() {
  const body = {
    username: val('nu-user'), password: val('nu-pass'), email: val('nu-email'),
    name: val('nu-name'), is_admin: document.getElementById('nu-admin').checked,
  };
  const res = await fetch('/api/admin/users', { method: 'POST', headers: ADMIN_HEADERS, body: JSON.stringify(body) });
  const d = await res.json();
  document.getElementById('u-msg').textContent = res.ok ? 'Created ' + d.username : (d.error || 'Failed');
  if (res.ok) { document.getElementById('nu-user').value = ''; document.getElementById('nu-pass').value = ''; }
  loadUsers();
}

async function deleteUser(name) {
  if (!confirm('Delete user ' + name + '?')) return;
  await fetch('/api/admin/users/' + encodeURIComponent(name), { method: 'DELETE', headers: ADMIN_HEADERS });
  loadUsers();
}

async function loadApps() {
  const res = await fetch('/api/admin/apps');
  const data = await res.json();
  const t = document.getElementById('apps-table');
  let rows = '';
  for (const a of data.apps || []) {
    rows += `<tr><td class="td-name">${escapeHtml(a.name)}</td><td><code>${escapeHtml(a.id)}</code></td>` +
      `<td>${a.public ? 'Public' : 'Confidential'}</td><td>${(a.redirect_uris || []).map(escapeHtml).join('<br>')}</td>` +
      `<td><button class="btn btn-danger btn-sm" onclick="deleteApp('${escapeHtml(a.id)}')">Delete</button></td></tr>`;
  }
  t.innerHTML = rows || '<tr class="empty-row"><td colspan="5">No applications</td></tr>';
}

async function createApp() {
  const body = { name: val('na-name'), redirect_uris: [val('na-uri')], public: document.getElementById('na-public').checked };
  const res = await fetch('/api/admin/apps', { method: 'POST', headers: ADMIN_HEADERS, body: JSON.stringify(body) });
  const d = await res.json();
  document.getElementById('a-msg').textContent = res.ok ? ('Created — secret: ' + (d.client_secret || '(public)')) : (d.error || 'Failed');
  loadApps();
}

async function deleteApp(id) {
  if (!confirm('Delete app ' + id + '?')) return;
  await fetch('/api/admin/apps/' + encodeURIComponent(id), { method: 'DELETE', headers: ADMIN_HEADERS });
  loadApps();
}

async function loadProviders() {
  const res = await fetch('/api/admin/providers');
  const data = await res.json();
  const t = document.getElementById('prov-table');
  let rows = '';
  for (const p of data.providers || []) {
    rows += `<tr><td class="td-name">${escapeHtml(p.name)}</td><td><code>${escapeHtml(p.id)}</code></td><td>${escapeHtml(p.kind)}</td>` +
      `<td>${p.enabled ? '<span class="badge badge-green">enabled</span>' : '<span class="badge badge-red">disabled</span>'}</td>` +
      `<td><button class="btn btn-danger btn-sm" onclick="deleteProvider('${escapeHtml(p.id)}')">Delete</button></td></tr>`;
  }
  t.innerHTML = rows || '<tr class="empty-row"><td colspan="5">No external providers — add one with the CLI</td></tr>';
}

async function deleteProvider(id) {
  if (!confirm('Delete provider ' + id + '?')) return;
  await fetch('/api/admin/providers/' + encodeURIComponent(id), { method: 'DELETE', headers: ADMIN_HEADERS });
  loadProviders();
}

async function loadAudit() {
  const res = await fetch('/api/admin/audit?limit=50');
  const data = await res.json();
  const t = document.getElementById('audit-table');
  let rows = '';
  for (const e of data.audit || []) {
    rows += `<tr><td class="td-mono">${escapeHtml(e.at)}</td><td>${escapeHtml(e.event)}</td>` +
      `<td class="td-mono">${escapeHtml(e.subject)}</td><td class="td-mono">${escapeHtml(e.client_id)}</td>` +
      `<td>${escapeHtml(e.ip)}</td><td>${escapeHtml(e.detail)}</td></tr>`;
  }
  t.innerHTML = rows || '<tr class="empty-row"><td colspan="6">No audit entries yet</td></tr>';
}

function val(id) { return document.getElementById(id).value; }

document.addEventListener('DOMContentLoaded', function () {
  loadUsers();
  loadApps();
  loadProviders();
  loadAudit();
});

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
      `<td><button class="btn btn-sm" onclick="showProvider('${escapeHtml(p.id)}')">Show</button> ` +
      `<button class="btn btn-sm" onclick="editProvider('${escapeHtml(p.id)}')">Edit</button> ` +
      `<button class="btn btn-danger btn-sm" onclick="deleteProvider('${escapeHtml(p.id)}')">Delete</button></td></tr>`;
  }
  t.innerHTML = rows || '<tr class="empty-row"><td colspan="5">No external providers yet</td></tr>';
}

// Mirrors `access-nex provider add`: name + client credentials required, a
// template (google/github/...) prefills endpoints, redirect URL is optional.
async function createProvider() {
  const body = {
    name: val('np-name'), template: val('np-template'),
    client_id: val('np-client-id'), client_secret: val('np-client-secret'),
    redirect_url: val('np-redirect'),
  };
  const res = await fetch('/api/admin/providers', { method: 'POST', headers: ADMIN_HEADERS, body: JSON.stringify(body) });
  const d = await res.json();
  document.getElementById('p-msg').textContent = res.ok ? 'Added ' + d.name + ' (' + d.kind + ')' : (d.error || 'Failed');
  if (res.ok) {
    for (const id of ['np-name', 'np-client-id', 'np-client-secret', 'np-redirect']) document.getElementById(id).value = '';
  }
  loadProviders();
}

// Mirrors `access-nex provider show`: full details, secret masked server-side.
async function showProvider(id) {
  const res = await fetch('/api/admin/providers/' + encodeURIComponent(id));
  const d = await res.json();
  const panel = document.getElementById('prov-details');
  if (!res.ok) { panel.style.display = ''; panel.textContent = d.error || 'Failed to load provider'; return; }
  const fields = [
    ['ID', d.id], ['Name', d.name], ['Kind', d.kind], ['Template', d.template],
    ['Client ID', d.client_id], ['Client Secret', d.client_secret],
    ['Redirect URL', d.redirect_url], ['Authorization URL', d.authorization_url],
    ['Access Token URL', d.access_token_url], ['Resource URL', d.resource_url],
    ['Logout URL', d.logout_url], ['User Identifier', d.user_identifier],
    ['Scopes', (d.scopes || []).join(' ')], ['Enabled', String(d.enabled)],
    ['Created', d.created_at], ['Updated', d.updated_at],
  ];
  let rows = '';
  for (const [k, v] of fields) {
    rows += `<tr><td class="td-name" style="white-space:nowrap">${escapeHtml(k)}</td><td class="td-mono">${escapeHtml(v || '—')}</td></tr>`;
  }
  panel.style.display = '';
  panel.innerHTML = `<strong>Provider details</strong> ` +
    `<button class="btn btn-sm" onclick="closeProviderPanel()">Close</button>` +
    `<table style="margin-top:8px">${rows}</table>`;
}

// The editable fields of `access-nex provider update`, in panel-form order.
const PROVIDER_EDIT_FIELDS = [
  ['name', 'Name'], ['client_id', 'Client ID'], ['client_secret', 'Client Secret (blank = keep current)'],
  ['redirect_url', 'Redirect URL'], ['authorization_url', 'Authorization URL'],
  ['access_token_url', 'Access Token URL'], ['resource_url', 'Resource URL'],
  ['logout_url', 'Logout URL'], ['user_identifier', 'User Identifier'], ['scopes', 'Scopes (space-separated)'],
];

// Mirrors `access-nex provider update`: prefilled form, empty fields keep
// their current value.
async function editProvider(id) {
  const res = await fetch('/api/admin/providers/' + encodeURIComponent(id));
  const d = await res.json();
  const panel = document.getElementById('prov-details');
  panel.style.display = '';
  if (!res.ok) { panel.textContent = d.error || 'Failed to load provider'; return; }
  let inputs = '';
  for (const [key, label] of PROVIDER_EDIT_FIELDS) {
    const type = key === 'client_secret' ? 'password' : 'text';
    inputs += `<div class="field"><label for="pe-${key}">${escapeHtml(label)}</label>` +
      `<input type="${type}" id="pe-${key}" style="min-width:320px"></div>`;
  }
  panel.innerHTML = `<strong>Edit provider <code>${escapeHtml(id)}</code></strong>` +
    `<div style="margin-top:8px">${inputs}</div>` +
    `<button class="btn btn-primary btn-sm" onclick="saveProvider('${escapeHtml(id)}')">Save</button> ` +
    `<button class="btn btn-sm" onclick="closeProviderPanel()">Cancel</button>` +
    `<span class="msg" id="pe-msg"></span>`;
  // Prefill via the DOM (not value= attributes) so stored URLs with quotes
  // can't break out of the markup.
  for (const [key] of PROVIDER_EDIT_FIELDS) {
    if (key === 'client_secret') continue;
    const v = key === 'scopes' ? (d.scopes || []).join(' ') : (d[key] || '');
    document.getElementById('pe-' + key).value = v;
  }
}

async function saveProvider(id) {
  const body = {};
  for (const [key] of PROVIDER_EDIT_FIELDS) {
    const v = val('pe-' + key).trim();
    if (!v) continue;
    body[key] = key === 'scopes' ? v.split(/[\s,]+/).filter(Boolean) : v;
  }
  const res = await fetch('/api/admin/providers/' + encodeURIComponent(id), {
    method: 'PUT', headers: ADMIN_HEADERS, body: JSON.stringify(body),
  });
  const d = await res.json();
  if (res.ok) {
    closeProviderPanel();
  } else {
    document.getElementById('pe-msg').textContent = d.error || 'Failed';
  }
  loadProviders();
}

function closeProviderPanel() {
  const panel = document.getElementById('prov-details');
  panel.style.display = 'none';
  panel.innerHTML = '';
}

async function deleteProvider(id) {
  if (!confirm('Delete provider ' + id + '?')) return;
  await fetch('/api/admin/providers/' + encodeURIComponent(id), { method: 'DELETE', headers: ADMIN_HEADERS });
  closeProviderPanel();
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

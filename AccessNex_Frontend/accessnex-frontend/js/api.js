/* ── AccessNex API Client ─────────────────────────────────────────────────── */
/* Connects to David's Go backend. Update API_BASE to match his server URL.   */

const API_BASE = "http://localhost:8080";

/* ── Token / session management ───────────────────────────────────────────── */
const Auth = {
  getToken:    ()  => localStorage.getItem("accessnex_token"),
  setToken:    (t) => localStorage.setItem("accessnex_token", t),
  clearToken:  ()  => localStorage.removeItem("accessnex_token"),
  getUser: () => {
    const t = Auth.getToken();
    if (!t) return null;
    try {
      const payload = JSON.parse(atob(t.split(".")[1]));
      return { username: payload.sub, role: payload.role };
    } catch { return null; }
  },
  isLoggedIn: () => !!Auth.getToken(),
  logout: () => {
    Auth.clearToken();
    /* Try to hit the Go backend logout endpoint before redirecting */
    fetch(`${API_BASE}/portal/logout`, { method: "POST", credentials: "include" })
      .catch(() => {})
      .finally(() => { window.location.href = "/index.html"; });
  },
};

/* ── Core fetch wrapper ────────────────────────────────────────────────────── */
async function apiFetch(path, options = {}) {
  const token = Auth.getToken();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "include",   /* include cookies for Go session support */
  });

  if (res.status === 401) { Auth.logout(); return; }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Unknown error" }));
    throw new Error(err.detail || err.error || "Request failed");
  }
  if (res.status === 204) return null;
  return res.json();
}

/* ── Auth endpoints (maps to David's /auth/* or /login routes) ────────────── */
const AuthAPI = {
  /* POST /token or /login — adjust path to match David's actual login route */
  login: async (username, password) => {
    const body = new URLSearchParams({ username, password, grant_type: "password" });
    const res = await fetch(`${API_BASE}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      credentials: "include",
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error_description: "Login failed" }));
      throw new Error(err.error_description || err.detail || "Login failed");
    }
    return res.json();   /* expects { access_token, token_type } */
  },

  /* GET /userinfo — standard OIDC userinfo endpoint */
  me: () => apiFetch("/userinfo"),
};

/* ── User endpoints ────────────────────────────────────────────────────────── */
/* NOTE: David's backend may expose these under /api/users or similar.         */
/* Update paths here once you have his route list.                             */
const UsersAPI = {
  list:   ()         => apiFetch("/users/"),
  get:    (id)       => apiFetch(`/users/${id}`),
  create: (data)     => apiFetch("/users/", { method: "POST", body: JSON.stringify(data) }),
  update: (id, data) => apiFetch(`/users/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  delete: (id)       => apiFetch(`/users/${id}`, { method: "DELETE" }),
};

/* ── App endpoints (maps to Go's /apps routes) ─────────────────────────────── */
const AppsAPI = {
  list:   ()         => apiFetch("/apps"),
  get:    (id)       => apiFetch(`/apps/${id}`),
  create: (data)     => apiFetch("/apps", { method: "POST", body: JSON.stringify(data) }),
  update: (id, data) => apiFetch(`/apps/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  delete: (id)       => apiFetch(`/apps/${id}`, { method: "DELETE" }),
};

/* ── Provider endpoints ────────────────────────────────────────────────────── */
const ProvidersAPI = {
  list:   ()         => apiFetch("/oauth/providers"),
  get:    (id)       => apiFetch(`/providers/${id}`),
  create: (data)     => apiFetch("/providers", { method: "POST", body: JSON.stringify(data) }),
  update: (id, data) => apiFetch(`/providers/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  delete: (id)       => apiFetch(`/providers/${id}`, { method: "DELETE" }),
};

/* ── Portal endpoints (maps to Go's /portal/* routes) ─────────────────────── */
const PortalAPI = {
  /* GET /userinfo — signed-in user profile */
  profile:         ()       => apiFetch("/userinfo"),

  /* Grants (authorized apps) */
  listGrants:      ()       => apiFetch("/portal/grants"),
  revokeGrant:     (cid)    => apiFetch("/portal/grants/revoke", { method: "POST", body: JSON.stringify({ client_id: cid }) }),

  /* Sessions */
  listSessions:    ()       => apiFetch("/portal/sessions"),
  revokeSession:   (sid)    => apiFetch("/portal/sessions/revoke", { method: "POST", body: JSON.stringify({ session_id: sid }) }),

  /* Linked identities */
  listIdentities:  ()       => apiFetch("/portal/identities"),
  unlinkIdentity:  (id)     => apiFetch("/portal/identities/unlink", { method: "POST", body: JSON.stringify({ identity_id: id }) }),

  /* Password change */
  changePassword:  (cur, nw) => apiFetch("/portal/password", { method: "POST", body: JSON.stringify({ current_password: cur, new_password: nw }) }),

  /* Server stats */
  stats:           ()       => apiFetch("/portal/stats"),
};

/* ── OAuth config helper ───────────────────────────────────────────────────── */
const OAuthAPI = {
  /* Discovery doc — tells us the issuer and all endpoint URLs */
  discovery: () => apiFetch("/.well-known/openid-configuration"),
};

/* ── Toast helper ──────────────────────────────────────────────────────────── */
function showToast(msg, duration = 3000) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), duration);
}

/* ── Auth guard ────────────────────────────────────────────────────────────── */
function requireAuth() {
  if (!Auth.isLoggedIn()) window.location.href = "/index.html";
}

/* ── Populate nav user info ────────────────────────────────────────────────── */
function initNav() {
  const user = Auth.getUser();
  if (!user) return;
  const avatar   = document.getElementById("navAvatar");
  const username = document.getElementById("navUsername");
  if (avatar)   avatar.textContent   = user.username.slice(0, 2).toUpperCase();
  if (username) username.textContent = user.username;
}

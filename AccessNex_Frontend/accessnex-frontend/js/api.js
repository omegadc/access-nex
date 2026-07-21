/* ── AccessNex API Client ─────────────────────────────────────────────────── */

const API_BASE = "http://localhost:8000";

/* Token management */
const Auth = {
  getToken: () => localStorage.getItem("accessnex_token"),
  setToken: (t) => localStorage.setItem("accessnex_token", t),
  clearToken: () => localStorage.removeItem("accessnex_token"),
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
    window.location.href = "/index.html";
  },
};

/* Core fetch wrapper */
async function apiFetch(path, options = {}) {
  const token = Auth.getToken();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  if (res.status === 401) { Auth.logout(); return; }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Unknown error" }));
    throw new Error(err.detail || "Request failed");
  }

  if (res.status === 204) return null;
  return res.json();
}

/* Auth endpoints */
const AuthAPI = {
  login: async (username, password) => {
    const body = new URLSearchParams({ username, password });
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Login failed" }));
      throw new Error(err.detail || "Login failed");
    }
    return res.json();
  },
  me: () => apiFetch("/auth/me"),
};

/* User endpoints */
const UsersAPI = {
  list:   ()           => apiFetch("/users/"),
  get:    (id)         => apiFetch(`/users/${id}`),
  create: (data)       => apiFetch("/users/", { method: "POST", body: JSON.stringify(data) }),
  update: (id, data)   => apiFetch(`/users/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  delete: (id)         => apiFetch(`/users/${id}`, { method: "DELETE" }),
};

/* App endpoints */
const AppsAPI = {
  list:   ()           => apiFetch("/apps/"),
  get:    (id)         => apiFetch(`/apps/${id}`),
  create: (data)       => apiFetch("/apps/", { method: "POST", body: JSON.stringify(data) }),
  update: (id, data)   => apiFetch(`/apps/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  delete: (id)         => apiFetch(`/apps/${id}`, { method: "DELETE" }),
};

/* Provider endpoints */
const ProvidersAPI = {
  list:   ()           => apiFetch("/providers/"),
  get:    (id)         => apiFetch(`/providers/${id}`),
  create: (data)       => apiFetch("/providers/", { method: "POST", body: JSON.stringify(data) }),
  update: (id, data)   => apiFetch(`/providers/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  delete: (id)         => apiFetch(`/providers/${id}`, { method: "DELETE" }),
};

/* ── Toast helper ─────────────────────────────────────────────────────────── */
function showToast(msg, duration = 3000) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), duration);
}

/* ── Redirect if not logged in ────────────────────────────────────────────── */
function requireAuth() {
  if (!Auth.isLoggedIn()) window.location.href = "/index.html";
}

/* ── Populate nav user info ───────────────────────────────────────────────── */
function initNav() {
  const user = Auth.getUser();
  if (!user) return;
  const avatar = document.getElementById("navAvatar");
  const username = document.getElementById("navUsername");
  if (avatar) avatar.textContent = user.username.slice(0, 2).toUpperCase();
  if (username) username.textContent = user.username;
}

function injectNav(activePage) {
  const navHTML = `
    <nav class="topnav">
      <div class="topnav-brand">
        <div class="brand-mark">
          <svg viewBox="0 0 24 24"><path d="M12 2L4 6v6c0 5.5 3.8 10.7 8 12 4.2-1.3 8-6.5 8-12V6l-8-4z"/></svg>
        </div>
        <span class="topnav-name">AccessNex</span>
      </div>
      <div class="topnav-right">
        <div class="topnav-avatar" id="navAvatar">--</div>
        <span class="topnav-user" id="navUsername"></span>
        <button class="btn btn-danger btn-sm" onclick="Auth.logout()">Sign out</button>
      </div>
    </nav>

    <aside class="sidebar">
      <p class="nav-section">Main</p>
      <a class="nav-item ${activePage==='dashboard'?'active':''}" href="dashboard.html">
        <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>Overview
      </a>
      <a class="nav-item ${activePage==='access'?'active':''}" href="access.html">
        <svg viewBox="0 0 24 24"><path d="M15 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-8"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>Access log
      </a>
      <a class="nav-item ${activePage==='portal'?'active':''}" href="portal.html">
        <svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>My account
      </a>
      <p class="nav-section">Manage</p>
      <a class="nav-item ${activePage==='users'?'active':''}" href="users.html">
        <svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>Users
      </a>
      <a class="nav-item ${activePage==='apps'?'active':''}" href="apps.html">
        <svg viewBox="0 0 24 24"><rect x="2" y="2" width="9" height="9"/><rect x="13" y="2" width="9" height="9"/><rect x="2" y="13" width="9" height="9"/><rect x="13" y="13" width="9" height="9"/></svg>Applications
      </a>
      <a class="nav-item ${activePage==='providers'?'active':''}" href="providers.html">
        <svg viewBox="0 0 24 24"><path d="M18 20V10"/><path d="M12 20V4"/><path d="M6 20v-6"/></svg>Providers
      </a>
      <a class="nav-item ${activePage==='oauth'?'active':''}" href="oauth-config.html">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M8.56 2.75c4.37 6.03 6.02 9.42 8.03 17.72m2.54-15.38c-3.72 4.35-8.94 5.66-16.88 5.85m19.5 1.9c-3.5-.93-6.63-.82-8.94 0-2.58.92-5.01 2.86-7.44 6.32"/></svg>OAuth config
      </a>
      <p class="nav-section">System</p>
      <a class="nav-item ${activePage==='settings'?'active':''}" href="settings.html">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>Settings
      </a>
    </aside>

    <div id="toast"></div>
  `;
  document.body.insertAdjacentHTML("afterbegin", navHTML);
  initNav();
}

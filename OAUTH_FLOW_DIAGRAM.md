# OAuth/OIDC Flow Diagram for Access-Nex + Portainer

## Complete Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PORTAINER OAUTH SETUP                           │
└─────────────────────────────────────────────────────────────────────────┘

Step 1: SETUP PHASE (One-time configuration)
═══════════════════════════════════════════════════════════════════════════

┌────────────────┐              ┌──────────────────────────┐
│  Access-Nex    │              │    Portainer Admin       │
│   Server       │              │    Settings → OAuth      │
│                │              │                          │
│ Create App:    │              │ Paste Configuration:     │
│ app create ... │─────────────>│ - Client ID              │
│                │              │ - Client Secret          │
│ Get Details:   │<─────────────│ - Auth URL               │
│ app list       │              │ - Token URL              │
└────────────────┘              │ - User Info URL          │
                                │ - Redirect URL           │
                                │ - Logout URL             │
                                │ - Scopes                 │
                                └──────────────────────────┘


Step 2: USER LOGIN PHASE (Every login)
═══════════════════════════════════════════════════════════════════════════

                    User Browser
                       │
                       │ 1. Clicks "Login with OAuth"
                       ▼
        ┌──────────────────────────────────┐
        │       Portainer UI                │
        │  [Login with OAuth Button]        │
        └──────────────────────────────────┘
                       │
                       │ 2. Redirects to Authorization URL
                       │    /authorize?client_id=...&redirect_uri=...
                       ▼
        ┌──────────────────────────────────┐
        │      Access-Nex Server           │
        │    /authorize endpoint            │
        │                                   │
        │  [Shows Login Form]               │
        │   Username: ______                │
        │   Password: ______                │
        │   [Sign in]                       │
        └──────────────────────────────────┘
                       │
                       │ 3. User enters credentials
                       ▼
        ┌──────────────────────────────────┐
        │   Access-Nex Verification        │
        │   - Check username/password      │
        │   - Verify redirect_uri          │
        │   - Generate authorization code  │
        └──────────────────────────────────┘
                       │
                       │ 4. Redirects back to Portainer
                       │    with authorization code
                       ▼
        ┌──────────────────────────────────┐
        │       Portainer Backend          │
        │  Receives: code=ABC123...         │
        │                                   │
        │  5. Exchanges code for tokens:   │
        │  POST /token                      │
        │  - code: ABC123...                │
        │  - client_id: client-portainer   │
        │  - client_secret: ***            │
        └──────────────────────────────────┘
                       │
                       │ 6. Token exchange request
                       ▼
        ┌──────────────────────────────────┐
        │      Access-Nex Server           │
        │    /token endpoint                │
        │                                   │
        │  Returns:                         │
        │  - access_token (JWT)             │
        │  - id_token (JWT)                 │
        │  - refresh_token (30 days)        │
        │  - expires_in: 3600               │
        └──────────────────────────────────┘
                       │
                       │ 7. Tokens returned to Portainer
                       ▼
        ┌──────────────────────────────────┐
        │       Portainer Backend          │
        │                                   │
        │  8. Gets user info:              │
        │  GET /userinfo                    │
        │  Header: Authorization: Bearer..  │
        └──────────────────────────────────┘
                       │
                       │ 9. User info request
                       ▼
        ┌──────────────────────────────────┐
        │      Access-Nex Server           │
        │    /userinfo endpoint             │
        │                                   │
        │  Returns user profile:            │
        │  {                                │
        │    "sub": "user-alice-...",       │
        │    "preferred_username": "alice", │
        │    "name": "Alice Smith",         │
        │    "email": "alice@example.com"   │
        │  }                                │
        └──────────────────────────────────┘
                       │
                       │ 10. User profile received
                       ▼
        ┌──────────────────────────────────┐
        │       Portainer Frontend         │
        │                                   │
        │  ✅ LOGGED IN AS: Alice Smith     │
        │                                   │
        │  [Portainer Dashboard]            │
        │  [Home] [Containers] [...] [Exit]│
        └──────────────────────────────────┘


Step 3: LOGOUT PHASE (When user clicks logout)
═══════════════════════════════════════════════════════════════════════════

        Portainer User
             │
             │ Clicks [Logout]
             ▼
    ┌─────────────────┐
    │ Access-Nex      │
    │ /end_session    │
    │ endpoint        │
    └─────────────────┘
             │
             ▼
    Session cleared, cookies deleted
    User logged out from both systems


CONFIGURATION MAPPING
═══════════════════════════════════════════════════════════════════════════

access-nex                              Portainer Settings
───────────────────────────────────────────────────────────────────────────
./access-nex app create                 Client ID & Client Secret
  --client-id "client-portainer-xxx"    └─> Copy to Portainer
  --client-secret "secret-abc..."

https://server:8080/authorize           Authorization Endpoint
https://server:8080/token               Access Token Endpoint  
https://server:8080/userinfo            Resource Endpoint
https://server:8080/end_session         Logout Endpoint

Provided by Portainer:                  Redirect URI
https://portainer.example.com/...       └─> Register in app create


KEY OAUTH ENDPOINTS
═══════════════════════════════════════════════════════════════════════════

1. GET /authorize
   ├─ Shows login form
   ├─ Validates request parameters
   ├─ Generates auth code on success
   └─ Redirects back with code

2. POST /token
   ├─ Verifies authorization code
   ├─ Validates client credentials
   ├─ Generates JWT tokens
   └─ Returns access_token, id_token, refresh_token

3. GET /userinfo
   ├─ Requires Bearer token
   ├─ Returns authenticated user profile
   ├─ Claims include: sub, preferred_username, email, name
   └─ Used to populate user info in Portainer

4. GET /end_session
   ├─ Clears server-side session
   ├─ Deletes session cookies
   └─ Optional, called on logout


QUICK START COMMANDS
═══════════════════════════════════════════════════════════════════════════

# 1. Create application for Portainer
./access-nex app create \
  --name "Portainer" \
  --redirect-uri "https://portainer.example.com/auth/oauth2/callback"

# 2. Create test user
./access-nex user add \
  --username testuser \
  --password testpass \
  --email test@example.com \
  --name "Test User"

# 3. Start server
./access-nex server --addr :8080

# 4. View app details (for Portainer config)
./access-nex app list

# 5. View user to verify
./access-nex user list


SAMPLE OAUTH RESPONSE FLOW
═══════════════════════════════════════════════════════════════════════════

Browser: GET /authorize?client_id=...&redirect_uri=...&response_type=code
  ↓
Server: Shows login form
  ↓
Browser: POST /authorize with username/password
  ↓
Server: Verifies credentials, generates code
  ↓
Browser: Redirected to redirect_uri?code=ABC123&state=...
  ↓
Backend: POST /token with code, client_id, client_secret
  ↓
Server: Verifies code and secret, returns tokens
  ↓
Backend: GET /userinfo with Bearer token
  ↓
Server: Returns user profile in JSON
  ↓
Frontend: Display user as logged in ✅


SECURITY NOTES
═══════════════════════════════════════════════════════════════════════════

✅ Client Secret: Sent only in backend (never in browser)
✅ Authorization Code: Short-lived (5 minutes), single-use
✅ Access Token: JWT format, 1 hour validity
✅ Refresh Token: Long-lived (30 days), can get new access tokens
✅ HTTPS Recommended: Use https:// in production (not http://)
✅ State Parameter: Prevents CSRF attacks (OAuth best practice)
✅ PKCE: For public clients (mobile apps) - not needed for web apps


OAUTH PARAMETER MEANINGS
═══════════════════════════════════════════════════════════════════════════

response_type=code           → Use OAuth authorization code flow
client_id=...                → Application identifier
redirect_uri=...             → Where to send user after auth
scope=openid profile email   → What info to access
state=...                    → CSRF protection token
nonce=...                    → Replay attack prevention
code_challenge/verifier      → PKCE for mobile apps
grant_type=authorization_code → Exchange code for tokens
grant_type=refresh_token     → Get new access token
```

## Common Issues & Their Position in the Flow

```
Issue                          Flow Position    Solution
───────────────────────────────────────────────────────────────────────────
"Invalid Client ID"            Step 4           Check client_id in /authorize call
"Redirect URI Mismatch"        Step 4           Verify redirect_uri matches registration
"Invalid Client Secret"        Step 6           Check secret in /token request
"Invalid Code"                 Step 6           Code expired or already used
"Token Expired"                Step 9           Use refresh_token to get new token
"User Not Found"               Step 10          Create user in access-nex first
"Cannot Reach Server"          All Steps        Check server is running
"HTTPS Certificate Error"      All Steps        Use http:// for localhost
```

---

**Legend**:
- `→` Flow direction
- `GET/POST` HTTP method
- `[...]` User action or display
- `{...}` JSON response

---

This diagram shows the complete OAuth 2.0 / OpenID Connect authentication flow 
between Portainer and your access-nex server!

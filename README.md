# access-nex

Multi factor access system. Ideally able to minimize unauthenticated & unauthorized access. access-nex OIDC/OAuth2 Integration Multi-factor access system with OIDC/OAuth2 support to minimize unauthenticated & unauthorized access.

Overview This implementation provides a complete OIDC/OAuth2 authentication flow using the Authorization Code Flow, ideal for web applications. It includes:

Reusable OIDC library (oidc.go) - Core OIDC/OAuth2 functionality Working example (main.go) - Full HTTP server with login/callback flow Support for generic OIDC providers (Google, Keycloak, Auth0, etc.) Features ✅ Authorization Code Flow with CSRF protection ✅ State token generation for security ✅ ID Token verification ✅ UserInfo endpoint integration ✅ Error handling and logging

Quick Start

Install Dependencies go mod tidy
Configure Environment Variables export OIDC_ISSUER="https://accounts.google.com" export OIDC_CLIENT_ID="your-client-id.apps.googleusercontent.com" export OIDC_CLIENT_SECRET="your-client-secret" export OIDC_REDIRECT_URL="http://localhost:8080/callback"
Run the Server go run main.go oidc.go Visit http://localhost:8080 and click "Login with OIDC Provider"
API Endpoints Endpoint Method Purpose / GET Home page with login link /login GET Initiates OIDC authorization flow /callback GET Handles OAuth2 callback with auth code /logout GET Logout endpoint OIDC Library (oidc.go) OIDCProvider Struct NewOIDCProvider(cfg) - Initialize provider GetAuthURL(state) - Get authorization URL ExchangeCode(code) - Exchange auth code for tokens VerifyToken(rawIDToken) - Verify & extract ID token claims GetUserInfo(token) - Fetch user info from UserInfo endpoint Helper Functions GenerateStateToken() - Create CSRF protection token Security Considerations ⚠️ Production Checklist:

Use HTTPS only Store tokens in HTTP-only, Secure cookies Use persistent session storage (not in-memory) Implement token refresh logic Add rate limiting Enable PKCE for additional security Supported OIDC Providers Google (https://accounts.google.com) Keycloak Auth0 Any compliant OIDC provider License See LICENSE file
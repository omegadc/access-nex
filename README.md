# Access-Nex: OIDC/OAuth2 Provider CLI

A command-line tool for managing an OpenID Connect (OIDC) and OAuth 2.0 provider. Easily create users, applications, and manage authentication flows for development and testing purposes.

## Table of Contents

- [Overview](#overview)
- [What is OAuth2/OIDC?](#what-is-oauth2oidc)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Commands](#cli-commands)
  - [Provider Commands](#provider-commands)
  - [User Commands](#user-commands)
  - [Application Commands](#application-commands)
  - [Integration Commands](#integration-commands)
  - [Server Commands](#server-commands)
  - [Shutdown Commands](#shutdown-commands)
- [Server Endpoints](#server-endpoints)
- [Using Access-Nex as an OIDC Provider](#using-access-nex-as-an-oidc-provider)
  - [OAuth Configuration for External Apps](#oauth-configuration-for-external-apps)
  - [Portainer Integration Guide](#portainer-integration-guide)
- [Example Workflows](#example-workflows)
- [Configuration](#configuration)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## Overview

Access-Nex is a lightweight OIDC/OAuth2 provider designed for development, testing, and demonstration purposes. It provides:

- **User Management**: Create, list, and delete users with usernames, emails, and profiles
- **Application Management**: Register OAuth2/OIDC applications (clients) with redirect URIs
- **Provider Configuration**: Set up your OIDC issuer with automatic key generation
- **Full OAuth2/OIDC Support**: Complete implementation of authorization code flow, refresh tokens, token introspection, and PKCE support
- **Persistent Storage**: All configuration saved to JSON files in `.access-nex/` directory
- **OIDC Discovery**: Standard OpenID Connect discovery endpoint for client discovery

## What is OAuth2/OIDC?

### OAuth 2.0
OAuth 2.0 is an authorization framework that enables third-party applications to obtain limited access to user accounts on an HTTP service without exposing passwords.

**Key Concepts:**
- **Authorization Server**: Issues tokens (this tool)
- **Client**: Application requesting access (your app)
- **Resource Owner**: The user
- **Authorization Code Flow**: The most secure flow for web apps
- **Access Token**: Short-lived token for API access
- **Refresh Token**: Long-lived token to get new access tokens

### OpenID Connect (OIDC)
OIDC is an authentication layer built on top of OAuth 2.0. It adds:

- **ID Token**: Contains user identity information (JWT format)
- **UserInfo Endpoint**: Get user profile information
- **Authentication**: Proves user identity, not just authorization
- **Discovery**: Standardized endpoints discovery

### Common Flows

**Authorization Code Flow (Recommended for web apps):**
```
1. User clicks "Login with Provider"
2. Redirects to /authorize endpoint
3. User authenticates and grants permission
4. Browser redirects back with authorization code
5. Application exchanges code for tokens at /token
6. Application receives access_token and id_token
```

**Public Client / PKCE Flow (Mobile & SPA apps):**
```
1. Client generates code_challenge
2. Redirects to /authorize with code_challenge
3. Gets authorization code
4. Exchanges code with code_verifier for tokens
5. No client_secret needed (can't be stored securely)
```

## Installation

### Requirements
- Go 1.22 or later
- Unix-like shell (bash, zsh, or similar on Windows use WSL/Git Bash)

### Build from Source

```bash
# Clone or navigate to the project
cd access-nex

# Build the executable
go build -o access-nex main.go

# Verify installation
./access-nex --help
```

## Quick Start

### 1. Initialize Provider

```bash
./access-nex provider init
```

Creates your OIDC provider with issuer URL `http://localhost:8080`

### 2. Create Users

```bash
# Create a user
./access-nex user add \
  --username alice \
  --password secret123 \
  --email alice@example.com \
  --name "Alice Smith"
```

### 3. Create an Application

```bash
# Create a confidential client (web app)
./access-nex app create \
  --name "My Web App" \
  --redirect-uri http://localhost:3000/callback
```

### 4. Start the Server

```bash
./access-nex server --addr :8080
```

Now you have a running OIDC provider!

## CLI Commands

### Provider Commands

#### Initialize Provider

```bash
./access-nex provider init [flags]
```

**Flags:**
- `--issuer` (string): Issuer URL (default: `http://localhost:8080`)

**Example:**
```bash
./access-nex provider init --issuer http://auth.example.com
```

**Output:**
```
✓ OIDC Provider initialized
  Issuer: http://localhost:8080
  Key ID: dev-key-1
  Endpoints:
    - /.well-known/openid-configuration
    - /authorize
    - /token
    - /userinfo
    - /jwks
```

#### Show Provider Information

```bash
./access-nex provider info
```

**Output:**
```
Provider Information:
  Issuer: http://localhost:8080
  Key ID: dev-key-1
  Users: 3
  Applications: 2
```

---

### User Commands

#### Add a User

```bash
./access-nex user add [flags]
```

**Flags:**
- `--username`, `-u` (string): Username (required)
- `--password`, `-p` (string): Password (required)
- `--email`, `-e` (string): Email address
- `--name`, `-n` (string): Full name

**Example:**
```bash
./access-nex user add \
  --username bob \
  --password pass456 \
  --email bob@example.com \
  --name "Bob Johnson"
```

**Output:**
```
✓ User 'bob' created successfully (subject: user-bob-1781630796707216300)
```

#### List Users

```bash
./access-nex user list
```

**Output:**
```
Username             Subject                                  Email                     Name
--------------------------------------------------------------------------------------------------------------
alice                user-alice-1781630789891128100           alice@example.com         Alice Smith
bob                  user-bob-1781630796707216300             bob@example.com           Bob Johnson
```

#### Delete a User

```bash
./access-nex user delete [flags]
```

**Flags:**
- `--username`, `-u` (string): Username to delete (required)

**Example:**
```bash
./access-nex user delete --username bob
```

**Output:**
```
✓ User 'bob' deleted
```

---

### Application Commands

#### Create an Application

```bash
./access-nex app create [flags]
```

**Flags:**
- `--name`, `-n` (string): Application name (required)
- `--redirect-uri`, `-r` (stringSlice): Redirect URI(s) (required, can be used multiple times)
- `--public`: Create as public client without secret (optional, default: false)

**Examples:**

**Confidential Client (Web App):**
```bash
./access-nex app create \
  --name "Web Dashboard" \
  --redirect-uri http://localhost:3000/callback
```

**Public Client (Mobile App or SPA):**
```bash
./access-nex app create \
  --name "Mobile App" \
  --redirect-uri myapp://callback \
  --public
```

**Multiple Redirect URIs:**
```bash
./access-nex app create \
  --name "Multi-Env App" \
  --redirect-uri http://localhost:3000/callback \
  --redirect-uri http://staging.example.com/callback \
  --redirect-uri http://prod.example.com/callback
```

**Output (Confidential):**
```
✓ Application 'Web Dashboard' created successfully
  Client ID: client-web-dashboard-1781630817949582700
  Client Secret: AkBswR7BytzMW_LXQ7WYSLrSeo-a12TJnHx146ztUBw
  Redirect URIs:
    - http://localhost:3000/callback
```

**Output (Public):**
```
✓ Application 'Mobile App' created successfully
  Client ID: client-mobile-app-1781630822560360800
  Type: Public (PKCE)
  Redirect URIs:
    - myapp://callback
```

#### List Applications

```bash
./access-nex app list
```

**Output:**
```
Client ID                      Name                           Type
---------------------------------------------------------------------------
client-mobile-app-1781630822560360800 Mobile App                     Public
  - Redirect: myapp://callback
client-web-app-1781630817949582700 Web App                        Confidential
  - Redirect: http://localhost:3000/callback
```

#### Delete an Application

```bash
./access-nex app delete [flags]
```

**Flags:**
- `--client-id`, `-c` (string): Client ID to delete (required)

**Example:**
```bash
./access-nex app delete --client-id client-web-app-1781630817949582700
```

**Output:**
```
✓ Application 'client-web-app-1781630817949582700' deleted
```

---

### Integration Commands

Integration commands allow you to manage external OAuth/OIDC providers. This is useful for storing and managing credentials for integrating third-party authentication services.

#### Add an Integration

```bash
./access-nex integration add [flags]
```

**Flags:**
- `--name`, `-n` (string): Integration name (required)
- `--provider`, `-p` (string): Provider template - "google", "github", "microsoft", or "custom" (default: "custom")
- `--client-id`, `-c` (string): OAuth Client ID (required)
- `--client-secret`, `-s` (string): OAuth Client Secret (required, encrypted)
- `--redirect-url`, `-r` (string): Redirect URL (required)
- `--authorization-url` (string): Authorization URL (overrides template)
- `--access-token-url` (string): Access Token URL (overrides template)
- `--resource-url` (string): Resource URL (overrides template)
- `--logout-url` (string): Logout URL (overrides template)
- `--user-identifier` (string): User Identifier field (overrides template)
- `--scopes` (string): Comma-separated scopes (overrides template)

**Examples:**

**With Provider Template (Google):**
```bash
./access-nex integration add \
  --name "Google OAuth" \
  --provider google \
  --client-id "1234567890-abc.apps.googleusercontent.com" \
  --client-secret "your-google-secret" \
  --redirect-url "http://localhost:3000/callback"
```

**With Custom Provider:**
```bash
./access-nex integration add \
  --name "Custom OAuth" \
  --provider custom \
  --client-id "custom-client-id" \
  --client-secret "custom-secret" \
  --redirect-url "http://localhost:3000/callback" \
  --authorization-url "https://auth.example.com/authorize" \
  --access-token-url "https://auth.example.com/token" \
  --resource-url "https://auth.example.com/userinfo" \
  --logout-url "https://auth.example.com/logout" \
  --user-identifier "email" \
  --scopes "openid,profile,email"
```

**Output:**
```
✓ Integration 'Google OAuth' created successfully
  ID: integration-google-oauth-1781633219744711500
  Type: oidc
  Provider: google
  Client ID: 1234567890-abc.apps.googleusercontent.com
  Redirect URL: http://localhost:3000/callback
  Scopes: openid, profile, email
```

#### List Integrations

```bash
./access-nex integration list
```

**Output:**
```
ID                                       Name                 Provider        Type      
------------------------------------------------------------------------------------------
integration-google-oauth-1781633219744711500 Google OAuth         google          oidc      
  Client ID: 1234567890-abc | Scopes: openid, profile, email
integration-my-github-1781633238380062300 My GitHub            github          oauth2    
  Client ID: github-client-id | Scopes: user, repo
```

#### Show Integration Details

```bash
./access-nex integration show [flags]
```

**Flags:**
- `--id`, `-i` (string): Integration ID (required)

**Example:**
```bash
./access-nex integration show --id integration-google-oauth-1781633219744711500
```

**Output:**
```
Integration Details: Google OAuth
------------------------------------------------------------
  ID:                  integration-google-oauth-1781633219744711500
  Name:                Google OAuth
  Type:                oidc
  Provider:            google
  Client ID:           1234567890-abc
  Client Secret:       your****
  Redirect URL:        http://localhost:3000/callback
  Authorization URL:   https://accounts.google.com/o/oauth2/v2/auth
  Access Token URL:    https://oauth2.googleapis.com/token
  Resource URL:        https://www.googleapis.com/oauth2/v2/userinfo
  User Identifier:     sub
  Scopes:              openid, profile, email
  Created At:          2026-06-16T14:06:59-04:00
```

#### Update an Integration

```bash
./access-nex integration update [flags]
```

**Flags:**
- `--id`, `-i` (string): Integration ID (required)
- All add command flags are available for updating

**Example:**
```bash
./access-nex integration update \
  --id integration-google-oauth-1781633219744711500 \
  --scopes "openid,profile,email,custom_scope"
```

#### Delete an Integration

```bash
./access-nex integration delete [flags]
```

**Flags:**
- `--id`, `-i` (string): Integration ID (required)

**Example:**
```bash
./access-nex integration delete --id integration-google-oauth-1781633219744711500
```

**Output:**
```
✓ Integration 'Google OAuth' deleted
```

---

#### Start the Server

```bash
./access-nex server [flags]
```

**Flags:**
- `--addr`, `-a` (string): Server address (default: `:8080`)

**Examples:**

```bash
# Start on default port 8080
./access-nex server

# Start on custom port
./access-nex server --addr :9000

# Start on specific interface and port
./access-nex server --addr 0.0.0.0:8080
```

**Output:**
```
✓ OIDC/OAuth2 provider starting on :8080
  Issuer: http://localhost:8080
  Users: 2
  Applications: 2
```

---

### Shutdown Commands

#### Stop the Server

**Method 1: Use Ctrl+C (Recommended)**

While the server is running in your terminal, press `Ctrl+C` to gracefully shut it down.

```bash
# In the terminal where server is running
Ctrl+C

# Output:
# Server stopped gracefully
```

**Method 2: Use the Shutdown Command**

In another terminal, run:

```bash
./access-nex shutdown
```

**Output:**
```
Shutting down server...
To manually stop the running server:

  Windows:
    Press Ctrl+C in the terminal where server is running
    Or use: taskkill /PID [process-id] /F

  Linux/Mac:
    Press Ctrl+C in the terminal where server is running
    Or use: kill -9 [process-id]

  Process ID can be found with:
    Windows: tasklist | findstr access-nex
    Linux/Mac: ps aux | grep access-nex
```

**Method 3: Kill the Process**

If the above methods don't work, find and kill the process:

**Windows:**
```bash
# Find the process ID
tasklist | findstr access-nex

# Kill it (replace [PID] with the actual process ID)
taskkill /PID [PID] /F
```

**Example:**
```bash
# List all processes
tasklist | findstr access-nex
# Output: access-nex.exe    1234   Console   0      5,120 K

# Kill the process with PID 1234
taskkill /PID 1234 /F
# Output: SUCCESS: The process with PID 1234 has been terminated.
```

**Linux/Mac:**
```bash
# Find the process ID
ps aux | grep access-nex

# Kill it
kill -9 [PID]
```

**Example:**
```bash
# Find process
ps aux | grep access-nex
# Output: user  1234  0.5  0.2  ... ./access-nex server

# Kill the process with PID 1234
kill -9 1234
```

#### Exit the CLI Program

The CLI program exits immediately after a command completes. To stop an interactive process:

- Press `Ctrl+C` to interrupt
- Close the terminal window
- Use `exit` command (if in interactive mode)

---

## Server Endpoints

Once the server is running, the following endpoints are available:

### Discovery Endpoints

#### OpenID Connect Discovery
```
GET /.well-known/openid-configuration
```
Returns provider metadata and supported features.

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

#### JWKS (JSON Web Key Set)
```
GET /jwks
```
Returns public keys for token verification.

```bash
curl http://localhost:8080/jwks
```

### Authentication Endpoints

#### Authorization
```
GET /authorize
POST /authorize
```
Initiates authentication flow. Redirects to login page if needed.

**Query Parameters:**
- `response_type=code` (required): Must be "code"
- `client_id` (required): Your application's client ID
- `redirect_uri` (required): Where to redirect after auth
- `scope` (optional): Space-separated scopes (default: "openid")
- `state` (recommended): CSRF protection
- `nonce` (optional): Request-specific value for ID token
- `code_challenge` (for PKCE): SHA256 hash of code_verifier
- `code_challenge_method` (for PKCE): "S256" or "plain"

**Example:**
```bash
curl "http://localhost:8080/authorize?client_id=my-app&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid+profile+email"
```

#### Token Exchange
```
POST /token
```
Exchanges authorization code or refresh token for access/ID tokens.

**Form Parameters:**
- `grant_type`: "authorization_code", "refresh_token", or "client_credentials"
- For auth code: `code`, `redirect_uri`, `client_id`, `client_secret` (if not public)
- For refresh: `refresh_token`, `client_id`, `client_secret` (if not public)
- For PKCE: `code_verifier`

**Example:**
```bash
curl -X POST http://localhost:8080/token \
  -d "grant_type=authorization_code" \
  -d "code=abc123..." \
  -d "client_id=my-app" \
  -d "client_secret=secret..." \
  -d "redirect_uri=http://localhost:3000/callback"
```

### User Information

#### UserInfo
```
GET /userinfo
```
Returns authenticated user's profile. Requires valid Bearer token.

**Headers:**
```
Authorization: Bearer {access_token}
```

**Example:**
```bash
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..." \
  http://localhost:8080/userinfo
```

### Token Management

#### Token Revocation
```
POST /revoke
```
Revokes an access or refresh token.

#### Token Introspection
```
POST /introspect
```
Checks if a token is valid and returns its claims.

### Session Management

#### End Session
```
GET /end_session
```
Clears user session and cookies.

### Application Registration

#### Dynamic Client Registration
```
POST /register
```
Allows dynamic registration of new clients (returns client_id and secret if confidential).

---

## Using Access-Nex as an OIDC Provider

Access-Nex can serve as a complete OAuth2/OIDC provider for external applications like Portainer, Grafana, Nextcloud, and others. This section explains how to configure external applications to authenticate against your access-nex instance.

### OAuth Configuration for External Apps

When integrating an external application with access-nex, you'll need to provide the following OAuth/OIDC configuration values:

#### Where to Find Each Configuration Value

1. **Client ID & Client Secret**
   - Generated when you create an application in access-nex
   - Command: `./access-nex app list` to view existing values
   - Or create new: `./access-nex app create --name "Portainer" --redirect-uri "https://portainer.example.com/auth/oauth2/callback"`

2. **Authorization URL (Auth URL)**
   - **Value**: `https://access-nex-server:8080/authorize`
   - Replace `access-nex-server` with your access-nex instance hostname/IP
   - Replace `8080` with the port if using a different one

3. **Access Token URL (Token URL)**
   - **Value**: `https://access-nex-server:8080/token`
   - Same host and port as Authorization URL

4. **Resource URL (User Info Endpoint)**
   - **Value**: `https://access-nex-server:8080/userinfo`
   - Used to fetch user profile information after authentication

5. **Redirect URL (Callback URL)**
   - **Value**: Provided by the external application
   - Example for Portainer: `https://portainer.example.com/auth/oauth2/callback`
   - This is where users are redirected after successful authentication
   - Must exactly match the URL registered in access-nex

6. **Logout URL (End Session Endpoint)**
   - **Value**: `https://access-nex-server:8080/end_session`
   - Optional, used for logout functionality

7. **User Identifier**
   - **Standard Options**: `sub`, `preferred_username`, `email`
   - **Default**: `sub` (subject - unique user identifier)
   - **For Username-based**: Use `preferred_username`
   - This field maps the OAuth claim to the user identifier in the external app

8. **Scopes**
   - **Recommended**: `openid profile email`
   - Space or comma-separated list
   - `openid`: Required for OIDC (includes user ID)
   - `profile`: Includes name, picture, etc.
   - `email`: Includes email address
   - **Example**: `openid profile email offline_access` (offline_access enables refresh tokens)

### Getting Your Provider's Discovery URL

Most OAuth clients can auto-discover endpoints using the OpenID Connect Discovery endpoint:
```
https://access-nex-server:8080/.well-known/openid-configuration
```

This endpoint returns all necessary configuration including:
- Authorization endpoint
- Token endpoint
- User info endpoint
- JWKS endpoint (public keys)
- Supported scopes and claims

**To view**: 
```bash
curl https://access-nex-server:8080/.well-known/openid-configuration
```

### Portainer Integration Guide

Portainer is a container management UI. Here's how to configure it to use access-nex for OAuth authentication.

#### Step 1: Create an Application in Access-Nex

```bash
./access-nex app create \
  --name "Portainer" \
  --redirect-uri "https://portainer.example.com/auth/oauth2/callback"
```

**Output:**
```
✓ Application 'Portainer' created successfully
  Client ID: client-portainer-1781633219744711500
  Client Secret: AbCdEfGhIjKlMnOpQrStUvWxYz1234567890
  Redirect URIs:
    - https://portainer.example.com/auth/oauth2/callback
```

**Save these values:**
- `Client ID`: `client-portainer-1781633219744711500`
- `Client Secret`: `AbCdEfGhIjKlMnOpQrStUvWxYz1234567890`

#### Step 2: Create a Test User (Optional)

```bash
./access-nex user add \
  --username portainer-user \
  --password secure-password \
  --email user@example.com \
  --name "Portainer User"
```

#### Step 3: Configure Portainer

In Portainer's admin settings, navigate to **Settings → OAuth** and enter:

| Field | Value |
|-------|-------|
| **Client ID** | `client-portainer-1781633219744711500` |
| **Client Secret** | `AbCdEfGhIjKlMnOpQrStUvWxYz1234567890` |
| **Authorization Server URL** | `https://access-nex-server:8080/authorize` |
| **Access Token Server URL** | `https://access-nex-server:8080/token` |
| **Resource Server URL** | `https://access-nex-server:8080/userinfo` |
| **Redirect URI** | `https://portainer.example.com/auth/oauth2/callback` |
| **Logout URI** | `https://access-nex-server:8080/end_session` |
| **User Identifier** | `preferred_username` |
| **Scopes** | `openid profile email` |

#### Step 4: Verify Configuration

1. Start your access-nex server: `./access-nex server --addr :8080`
2. In Portainer, click "Login with OAuth"
3. You should be redirected to access-nex login page
4. Enter credentials (e.g., `portainer-user` / `secure-password`)
5. Grant permissions if prompted
6. You should be redirected back to Portainer and logged in

### Common External Applications

These applications can all use access-nex as an OAuth/OIDC provider:

- **Portainer** - Container management (example above)
- **Grafana** - Monitoring and visualization
- **Nextcloud** - File synchronization and sharing
- **GitLab** - DevOps platform
- **Mattermost** - Team messaging
- **Keycloak** - Identity management
- **Custom Applications** - Any app supporting OAuth2/OIDC

Most of these have similar OAuth configuration sections in their admin settings.

---

### Workflow 1: Web Application (Authorization Code Flow)

**Setup:**
```bash
# Initialize provider
./access-nex provider init

# Create user
./access-nex user add --username testuser --password password123 --email user@example.com --name "Test User"

# Create web app
./access-nex app create --name "My App" --redirect-uri http://localhost:3000/callback

# Start server
./access-nex server
```

**In Your Application:**

```javascript
// Step 1: Redirect user to login
window.location.href = 'http://localhost:8080/authorize?' +
  'client_id=client-my-app-xxx&' +
  'redirect_uri=http://localhost:3000/callback&' +
  'response_type=code&' +
  'scope=openid profile email&' +
  'state=random123';

// Step 2: Handle callback (code will be in URL)
const params = new URLSearchParams(window.location.search);
const authCode = params.get('code');

// Step 3: Exchange code for tokens (backend)
const response = await fetch('http://localhost:8080/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authCode,
    client_id: 'client-my-app-xxx',
    client_secret: 'your-secret-here',
    redirect_uri: 'http://localhost:3000/callback'
  })
});

const tokens = await response.json();
// tokens contains: access_token, id_token, refresh_token, expires_in

// Step 4: Get user info
const userInfoResponse = await fetch('http://localhost:8080/userinfo', {
  headers: { 'Authorization': `Bearer ${tokens.access_token}` }
});

const userInfo = await userInfoResponse.json();
console.log('User:', userInfo);
```

### Workflow 2: Mobile/SPA Application (PKCE Flow)

**Setup:**
```bash
# Create public client for mobile/SPA
./access-nex app create --name "Mobile App" --redirect-uri myapp://callback --public
```

**In Your Mobile App:**

```javascript
// Step 1: Generate PKCE parameters
const codeVerifier = generateRandomString(43); // 43-128 chars
const codeChallenge = sha256(codeVerifier); // SHA256 hash
const state = generateRandomString(32);

// Step 2: Redirect to authorize
const authURL = 'http://localhost:8080/authorize?' +
  'client_id=client-mobile-app-xxx&' +
  'redirect_uri=myapp://callback&' +
  'response_type=code&' +
  'scope=openid profile&' +
  'code_challenge=' + codeChallenge + '&' +
  'code_challenge_method=S256&' +
  'state=' + state;

// Redirect user...

// Step 3: Handle callback with code
const code = getCodeFromCallback();

// Step 4: Exchange code for tokens (NO secret needed!)
const response = await fetch('http://localhost:8080/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    client_id: 'client-mobile-app-xxx',
    redirect_uri: 'myapp://callback',
    code_verifier: codeVerifier  // Secret sent here, not in client_secret
  })
});

const tokens = await response.json();
```

### Workflow 3: Token Refresh

```javascript
// After access_token expires, use refresh_token to get a new one
const response = await fetch('http://localhost:8080/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: savedRefreshToken,
    client_id: 'client-my-app-xxx',
    client_secret: 'your-secret-here'
  })
});

const newTokens = await response.json();
// Update your stored access_token and refresh_token
```

---

## Configuration

### Configuration Directory

All configuration is stored in `.access-nex/` directory:

- **provider.json**: Provider settings (issuer, key ID)
- **users.json**: Registered users with credentials
- **clients.json**: Registered OAuth2 applications

### Custom Configuration Path

```bash
./access-nex --config /path/to/config/dir user list
./access-nex --config ~/.access-nex-prod server
```

### Configuration File Examples

**provider.json:**
```json
{
  "issuer": "http://localhost:8080",
  "keyID": "dev-key-1"
}
```

**users.json:**
```json
{
  "alice": {
    "sub": "user-alice-12345",
    "username": "alice",
    "password": "hashed_password",
    "email": "alice@example.com",
    "name": "Alice Smith"
  }
}
```

**clients.json:**
```json
{
  "client-web-app-123": {
    "client_id": "client-web-app-123",
    "client_secret": "secret123...",
    "client_name": "Web App",
    "redirect_uris": ["http://localhost:3000/callback"],
    "public": false
  },
  "client-mobile-app-456": {
    "client_id": "client-mobile-app-456",
    "client_name": "Mobile App",
    "redirect_uris": ["myapp://callback"],
    "public": true
  }
}
```

---

## Security Considerations

### ⚠️ Development Only

This provider is designed for **development, testing, and educational purposes only**. Do NOT use in production environments.

### Security Notes

1. **Passwords**: Stored in plain text in JSON files. Use environment variables or encrypted storage in production.

2. **Tokens**: 
   - ID tokens expire in 1 hour
   - Access tokens expire in 1 hour
   - Refresh tokens expire in 30 days
   - In production, use shorter lifetimes and secure storage

3. **Client Secrets**: 
   - Generated randomly but displayed in CLI output
   - Never commit secrets to version control
   - Use environment variables in production

4. **HTTPS**: This tool uses HTTP by default. In production, always use HTTPS with valid certificates.

5. **CORS**: The server allows cross-origin requests with broad permissions. Restrict in production:
   ```
   Access-Control-Allow-Origin: http://localhost:3000  // Specific domain
   ```

6. **Key Rotation**: Use a single development key. Implement key rotation in production.

### Best Practices

- ✅ Use PKCE for mobile and SPA applications
- ✅ Always validate state parameter to prevent CSRF
- ✅ Store refresh tokens securely (secure cookies, encrypted storage)
- ✅ Implement token revocation
- ✅ Log authentication events
- ✅ Use short-lived tokens
- ✅ Rotate keys regularly
- ✅ Implement rate limiting
- ✅ Validate redirect URIs strictly

---

## Troubleshooting

### Issue: "command not found: access-nex"

**Solution:** Build the executable first:
```bash
go build -o access-nex main.go
```

Or use `./access-nex` (with `./` prefix) on Unix-like systems.

### Issue: "config directory not found"

**Solution:** The `.access-nex` directory is created automatically. If it fails:
```bash
mkdir -p .access-nex
./access-nex provider init
```

### Issue: "user already exists"

**Solution:** Users must have unique usernames. Either:
- Use a different username
- Delete the existing user first: `./access-nex user delete --username oldname`

### Issue: "Port already in use"

**Solution:** This means the server is already running on that port. Either:

1. **Use a different port:**
   ```bash
   ./access-nex server --addr :9000
   ```

2. **Stop the existing server:**
   ```bash
   # Method 1: Press Ctrl+C in the terminal where server is running
   
   # Method 2: Kill the process
   # On Linux/Mac
   lsof -i :8080
   kill -9 <PID>

   # On Windows
   netstat -ano | findstr :8080
   taskkill /PID <PID> /F
   ```

3. **Use the shutdown command:**
   ```bash
   ./access-nex shutdown
   ```

### Issue: "Provider not initialized"

**Solution:** Run initialization first:
```bash
./access-nex provider init
```

### Issue: Server responds with "unknown client_id"

**Solution:** Make sure the client was created:
```bash
./access-nex app list
# Copy the exact client_id from the output
```

### Issue: Redirect URI mismatch error

**Solution:** The redirect URI in your authorization request must exactly match a registered URI:
```bash
# See registered URIs:
./access-nex app list

# If needed, create a new app with correct URI:
./access-nex app create --name "MyApp" --redirect-uri http://localhost:3000/callback
```

### Issue: Cannot exchange authorization code

**Common causes:**
1. Code has expired (valid for 5 minutes)
2. Client secret is incorrect
3. Redirect URI doesn't match
4. Wrong client_id

**Solution:** Start a fresh authorization flow and immediately exchange the code.

### Issue: Invalid token at UserInfo endpoint

**Solution:** Ensure:
1. Access token is valid and not expired
2. Bearer token is in the Authorization header
3. Token includes "openid" scope

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/userinfo
```

### Issue: How to stop/shutdown the server

**Solution:** Use one of these methods:

1. **Press Ctrl+C** (Recommended - graceful shutdown)
   - Go to the terminal where the server is running
   - Press `Ctrl+C`

2. **Use the shutdown command**
   ```bash
   ./access-nex shutdown
   ```

3. **Kill the process**
   - Windows: `taskkill /PID <process-id> /F`
   - Linux/Mac: `kill -9 <process-id>`

4. **Find process ID if needed**
   - Windows: `tasklist | findstr access-nex`
   - Linux/Mac: `ps aux | grep access-nex`

---

## Common OAuth2/OIDC Terms

- **Authorization Code**: Temporary code exchanged for tokens
- **Access Token**: Token for accessing APIs
- **ID Token**: JWT containing user identity (OIDC specific)
- **Refresh Token**: Long-lived token for getting new access tokens
- **Client ID**: Public identifier for your application
- **Client Secret**: Confidential identifier (keep secret!)
- **Scope**: Permission requested (openid, profile, email, etc.)
- **PKCE**: Proof Key for Public Clients (for mobile/SPA apps)
- **State**: CSRF token to verify requests haven't been tampered with
- **Nonce**: One-time use value to prevent replay attacks
- **JWT**: JSON Web Token - format for access/ID tokens
- **JWKS**: JSON Web Key Set - public keys for token verification

---

## Getting Help

For issues or questions:
1. Check this README's Troubleshooting section
2. Review the example workflows
3. Check the server logs for error details
4. Verify all configuration with `./access-nex provider info`

---

## License

Development/Educational Use Only

---

**Made with ❤️ for OAuth2/OIDC learning and development**
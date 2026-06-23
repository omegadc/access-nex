#!/usr/bin/env bash
# portainer_oauth_test.sh
#
# Simulates the exact OAuth 2.0 / OIDC flow that Portainer Business Edition
# executes when a user clicks "Login with OAuth".  No browser or jq required —
# uses only curl and python3 (both are available on this system).
#
# Usage:
#   bash portainer_oauth_test.sh [--addr :8080] [--user USERNAME] [--pass PASSWORD]
# ---------------------------------------------------------------------------
set -euo pipefail

BINARY="./access-nex.exe"
ADDR=":8080"
TEST_USER="portainer-test"
TEST_PASS="portainer-pass"
TEST_EMAIL="portainer@example.com"
TEST_NAME="Portainer Test User"
PORTAINER_REDIRECT="http://localhost:9443/"

while [[ $# -gt 0 ]]; do
  case $1 in
    --addr)     ADDR="$2"; shift 2;;
    --user)     TEST_USER="$2"; shift 2;;
    --pass)     TEST_PASS="$2"; shift 2;;
    --redirect) PORTAINER_REDIRECT="$2"; shift 2;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done
BASE="http://localhost:${ADDR#:}"

PASS=0; FAIL=0
ok()   { echo "  ✓ $*"; ((PASS++)) || true; }
fail() { echo "  ✗ $*"; ((FAIL++)) || true; }
hdr()  { echo; echo "── $* ──────────────────────────────────────"; }

# Helper: extract a JSON string field without jq
jfield() {
  local json="$1" field="$2"
  echo "$json" | python3 -c "
import json,sys
d=json.load(sys.stdin)
v=d.get('$field','')
print('' if v is None else str(v))
" <<< "$json" 2>/dev/null || true
}

# ── 1. Ensure provider is initialized ────────────────────────────────────────
hdr "Setup"
$BINARY provider self init --issuer "$BASE" 2>/dev/null | tail -1 || true
ok "Provider: $BASE"

# ── 2. Ensure test user exists ────────────────────────────────────────────────
$BINARY user add -u "$TEST_USER" -p "$TEST_PASS" \
  -e "$TEST_EMAIL" -n "$TEST_NAME" 2>/dev/null \
  && ok "User '$TEST_USER' created" \
  || ok "User '$TEST_USER' already exists"

# ── 3. Register a Portainer OAuth application ─────────────────────────────────
hdr "Client Registration  (POST /register)"
REG=$(curl -sf -X POST "$BASE/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_name\": \"Portainer (test)\",
    \"redirect_uris\": [\"$PORTAINER_REDIRECT\"],
    \"token_endpoint_auth_method\": \"client_secret_post\"
  }")

CLIENT_ID=$(jfield "$REG" client_id)
CLIENT_SECRET=$(jfield "$REG" client_secret)

[[ -n "$CLIENT_ID" ]]     && ok "Client ID:     $CLIENT_ID"     || { fail "Registration failed: $REG"; exit 1; }
[[ -n "$CLIENT_SECRET" ]] && ok "Client Secret: ${CLIENT_SECRET:0:12}…" || fail "No client_secret"

# ── 4. OIDC Discovery ────────────────────────────────────────────────────────
hdr "OIDC Discovery  (GET /.well-known/openid-configuration)"
DISC=$(curl -sf "$BASE/.well-known/openid-configuration")

chk_disc() {
  local f="$1" want="$2"
  local got; got=$(jfield "$DISC" "$f")
  [[ "$got" == "$want" ]] && ok "$f = $got" || fail "$f: want '$want', got '$got'"
}
chk_disc issuer                 "$BASE"
chk_disc authorization_endpoint "$BASE/authorize"
chk_disc token_endpoint         "$BASE/token"
chk_disc userinfo_endpoint      "$BASE/userinfo"
chk_disc jwks_uri               "$BASE/jwks"
chk_disc end_session_endpoint   "$BASE/end_session"

# ── 5. JWKS — RSA public key present ─────────────────────────────────────────
hdr "JWKS  (GET /jwks)"
JWKS=$(curl -sf "$BASE/jwks")
KTY=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d['keys'][0]['kty'])" <<< "$JWKS" 2>/dev/null)
ALG=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d['keys'][0]['alg'])" <<< "$JWKS" 2>/dev/null)
[[ "$KTY" == "RSA" ]]   && ok "Key type:  RSA"  || fail "Key type: $KTY"
[[ "$ALG" == "RS256" ]]  && ok "Algorithm: RS256" || fail "Algorithm: $ALG"

# ── 6. Authorization Code Flow ───────────────────────────────────────────────
hdr "Authorization Code Flow  (POST /authorize)"
STATE="ptst-$(python3 -c 'import secrets; print(secrets.token_hex(8))')"

AUTH_RESP=$(curl -sf -D - -o /dev/null \
  -X POST "$BASE/authorize" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$PORTAINER_REDIRECT" \
  --data-urlencode "scope=openid profile email" \
  --data-urlencode "state=$STATE" \
  --data-urlencode "username=$TEST_USER" \
  --data-urlencode "password=$TEST_PASS")

LOCATION=$(echo "$AUTH_RESP" | grep -i '^location:' | tr -d '\r' | sed 's/^[Ll]ocation: //')
[[ -n "$LOCATION" ]] || { fail "No Location header — check credentials"; echo "$AUTH_RESP"; exit 1; }
ok "Redirect received: ${LOCATION:0:70}…"

CODE=$(echo "$LOCATION"  | grep -o 'code=[^&]*'  | cut -d= -f2)
RET_STATE=$(echo "$LOCATION" | grep -o 'state=[^&]*' | cut -d= -f2)
RAW_ISS=$(echo "$LOCATION"  | grep -o 'iss=[^& ]*' | cut -d= -f2)
ISS=$(python3 -c "import urllib.parse,sys; print(urllib.parse.unquote(sys.stdin.read().strip()))" <<< "$RAW_ISS" 2>/dev/null || echo "$RAW_ISS")

[[ -n "$CODE" ]]             && ok "Auth code:      ${CODE:0:22}…" || fail "No code in redirect"
[[ "$RET_STATE" == "$STATE" ]] && ok "State:          matches"       || fail "State mismatch: '$RET_STATE' vs '$STATE'"
[[ "$ISS" == "$BASE" ]]      && ok "iss param:      $ISS"          || ok "iss param:      $ISS  (URL-encoded form)"

# ── 7. Token Exchange ─────────────────────────────────────────────────────────
hdr "Token Exchange  (POST /token)"
TOK=$(curl -sf -X POST "$BASE/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$PORTAINER_REDIRECT" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET")

ACCESS_TOKEN=$(jfield "$TOK" access_token)
ID_TOKEN=$(jfield "$TOK" id_token)
TOKEN_TYPE=$(jfield "$TOK" token_type)
EXPIRES_IN=$(jfield "$TOK" expires_in)
SCOPE=$(jfield "$TOK" scope)

[[ -n "$ACCESS_TOKEN" ]]   && ok "access_token:   received (${#ACCESS_TOKEN} chars)" || fail "No access_token"
[[ -n "$ID_TOKEN" ]]        && ok "id_token:       received (${#ID_TOKEN} chars)"     || fail "No id_token"
[[ "$TOKEN_TYPE" == "Bearer" ]] && ok "token_type:     Bearer"                        || fail "token_type: $TOKEN_TYPE"
ok "expires_in:     ${EXPIRES_IN}s"
ok "scope:          $SCOPE"

# ── 8. UserInfo — what Portainer reads to identify the user ──────────────────
hdr "UserInfo  (GET /userinfo)"
UI=$(curl -sf "$BASE/userinfo" -H "Authorization: Bearer $ACCESS_TOKEN")

UI_SUB=$(jfield "$UI" sub)
UI_NAME=$(jfield "$UI" name)
UI_EMAIL=$(jfield "$UI" email)
UI_UNAME=$(jfield "$UI" preferred_username)
UI_VER=$(jfield "$UI" email_verified)

[[ -n "$UI_SUB" ]]    && ok "sub:                $UI_SUB"   || fail "sub missing"
[[ -n "$UI_NAME" ]]   && ok "name:               $UI_NAME"  || fail "name missing"
[[ -n "$UI_EMAIL" ]]  && ok "email:              $UI_EMAIL" || fail "email missing"
[[ -n "$UI_UNAME" ]]  && ok "preferred_username: $UI_UNAME" || fail "preferred_username missing"
[[ "$UI_VER" == "True" || "$UI_VER" == "true" ]] \
                       && ok "email_verified:     true" \
                       || fail "email_verified: $UI_VER"

# ── 9. ID Token payload ───────────────────────────────────────────────────────
hdr "ID Token Claims (decoded)"
if [[ -n "$ID_TOKEN" ]]; then
  PAYLOAD_B64=$(echo "$ID_TOKEN" | cut -d. -f2)
  PAYLOAD=$(python3 -c "
import base64, json, sys
raw = sys.stdin.read().strip()
pad = 4 - len(raw)%4
try:
    d = json.loads(base64.urlsafe_b64decode(raw + '='*pad))
    for k in ['iss','sub','aud','email','name','preferred_username','exp','iat','auth_time']:
        if k in d: print(f'    {k}: {d[k]}')
except Exception as e:
    print(f'    (decode error: {e})')
" <<< "$PAYLOAD_B64" 2>/dev/null)
  echo "$PAYLOAD"
  ok "ID token decoded successfully"
fi

# ── 10. Token Introspection ───────────────────────────────────────────────────
hdr "Token Introspection  (POST /introspect)"
INTRO=$(curl -sf -X POST "$BASE/introspect" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$ACCESS_TOKEN")
ACTIVE=$(jfield "$INTRO" active)
[[ "$ACTIVE" == "True" || "$ACTIVE" == "true" ]] \
  && ok "Token is active"           || fail "Token inactive: $INTRO"
ok "client_id: $(jfield "$INTRO" client_id)"
ok "sub:       $(jfield "$INTRO" sub)"
ok "scope:     $(jfield "$INTRO" scope)"

# ── 11. Token Revocation ─────────────────────────────────────────────────────
hdr "Token Revocation  (POST /revoke)"
HTTP=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "$BASE/revoke" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$ACCESS_TOKEN")
[[ "$HTTP" == "200" ]] && ok "Revoke returned HTTP 200" || fail "Revoke HTTP $HTTP"

INTRO2=$(curl -sf -X POST "$BASE/introspect" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$ACCESS_TOKEN")
ACT2=$(jfield "$INTRO2" active)
[[ "$ACT2" == "False" || "$ACT2" == "false" ]] \
  && ok "Revoked token now inactive" || fail "Token still active after revoke"

# ── 12. End Session ───────────────────────────────────────────────────────────
hdr "End Session  (GET /end_session)"
HTTP=$(curl -sf -o /dev/null -w "%{http_code}" "$BASE/end_session")
[[ "$HTTP" == "200" ]] && ok "HTTP 200" || ok "HTTP $HTTP"

# ── Summary ───────────────────────────────────────────────────────────────────
hdr "Summary"
TOTAL=$((PASS+FAIL))
echo "  Passed: $PASS / $TOTAL"
if [[ $FAIL -gt 0 ]]; then
  echo "  Failed: $FAIL"
  exit 1
fi

echo
echo "  All checks passed ✓"
echo
echo "  ┌─ Portainer OAuth Settings ─────────────────────────────────────┐"
printf  "  │ %-24s %-38s │\n" "Provider:"           "Custom"
printf  "  │ %-24s %-38s │\n" "Client ID:"          "$CLIENT_ID"
printf  "  │ %-24s %-38s │\n" "Client Secret:"      "${CLIENT_SECRET:0:16}…"
printf  "  │ %-24s %-38s │\n" "Authorization URL:"  "$BASE/authorize"
printf  "  │ %-24s %-38s │\n" "Access Token URL:"   "$BASE/token"
printf  "  │ %-24s %-38s │\n" "Resource URL:"       "$BASE/userinfo"
printf  "  │ %-24s %-38s │\n" "Logout URL:"         "$BASE/end_session"
printf  "  │ %-24s %-38s │\n" "Redirect URL:"       "$PORTAINER_REDIRECT"
printf  "  │ %-24s %-38s │\n" "User Identifier:"    "email"
printf  "  │ %-24s %-38s │\n" "Scopes:"             "openid profile email"
printf  "  │ %-24s %-38s │\n" "Token Auth Method:"  "client_secret_post"
echo    "  └────────────────────────────────────────────────────────────────┘"
echo

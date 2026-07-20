package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/omegadc/access-nex/internal/models"
)

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write json: %v", err)
	}
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func esc(s string) string { return template.HTMLEscapeString(s) }

func parseScope(raw string) []string {
	seen := map[string]bool{}
	var scopes []string
	for _, s := range strings.Fields(strings.ReplaceAll(raw, ",", " ")) {
		if s != "" && !seen[s] {
			scopes = append(scopes, s)
			seen[s] = true
		}
	}
	return scopes
}

func hasScope(scopes []string, needle string) bool {
	for _, s := range scopes {
		if s == needle {
			return true
		}
	}
	return false
}

func bearerToken(r *http.Request) string {
	scheme, token := authHeaderToken(r)
	if !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return token
}

// authHeaderToken splits "Authorization: <scheme> <token>" into its parts,
// e.g. ("Bearer", "eyJ...") or ("DPoP", "eyJ...").
func authHeaderToken(r *http.Request) (scheme, token string) {
	h := r.Header.Get("Authorization")
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], strings.TrimSpace(parts[1])
}

func redirectAllowed(client *models.App, redirectURI string) bool {
	for _, allowed := range client.RedirectURIs {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

func verifyPKCE(challenge, method, verifier string) bool {
	if verifier == "" {
		return false
	}
	if method == "" || method == "plain" {
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(verifier)) == 1
	}
	if method == "S256" {
		sum := sha256.Sum256([]byte(verifier))
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(b64(sum[:]))) == 1
	}
	return false
}

func accessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return b64(sum[:len(sum)/2])
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

package server

// RFC 8693 OAuth 2.0 Token Exchange — lets a confidential client trade a
// token it already holds for a new one scoped to a different audience, for
// service-to-service delegation (service A calls service B "on behalf of"
// the original subject, without re-running the whole login flow).
//
// This implements the common subset: subject_token_type must be an access
// token issued by this server, the caller must authenticate as a
// confidential client, and the new token is issued for the same subject
// with the requested audience/scope (narrowed to the original token's
// scope). The `act` claim records which client performed the exchange, so
// downstream services can trace the delegation chain.

import (
	"net/http"
	"strings"
	"time"

	"github.com/omegadc/access-nex/internal/models"
)

const (
	tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessTokenType        = "urn:ietf:params:oauth:token-type:access_token"
)

func (s *Server) handleTokenExchangeGrant(w http.ResponseWriter, r *http.Request, client *models.App, jkt string) {
	if client.Public {
		writeOAuthError(w, http.StatusUnauthorized, "unauthorized_client", "Public clients cannot exchange tokens")
		return
	}
	subjectToken := r.Form.Get("subject_token")
	subjectTokenType := r.Form.Get("subject_token_type")
	if subjectToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing subject_token")
		return
	}
	if subjectTokenType != "" && subjectTokenType != accessTokenType {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Unsupported subject_token_type")
		return
	}

	original, err := s.store.GetAccessToken(subjectToken)
	if err != nil || original.Revoked || time.Now().After(original.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "subject_token is invalid or expired")
		return
	}

	audiences, err := s.parseAudiences(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", err.Error())
		return
	}
	// requested_token_type is accepted but we only ever issue access tokens.
	if rtt := r.Form.Get("requested_token_type"); rtt != "" && rtt != accessTokenType {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Unsupported requested_token_type")
		return
	}

	// Narrow to whatever subset of the original token's scope was requested;
	// an exchange can only shed privileges, never gain them.
	scope := original.Scope
	if requested := parseScope(r.Form.Get("scope")); len(requested) > 0 {
		scope = nil
		for _, sc := range requested {
			if hasScope(original.Scope, sc) {
				scope = append(scope, sc)
			}
		}
		if len(scope) == 0 {
			writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "Requested scope exceeds subject_token's scope")
			return
		}
	}

	record, err := s.issueAccessToken(client.ID, original.Subject, scope, audiences, jkt, client.ID)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not issue token")
		return
	}
	s.store.Audit("token_exchanged", original.Subject, client.ID, clientIP(r),
		client.ID+" now acting for subject_token originally issued to "+original.ClientID)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      record.Token,
		"issued_token_type": accessTokenType,
		"token_type":        tokenType(jkt),
		"expires_in":        int(time.Until(record.ExpiresAt).Seconds()),
		"scope":             strings.Join(scope, " "),
	})
}

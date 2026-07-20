package server

// Portal self-service: users manage their own grants, sessions, password,
// and linked external identities without needing an admin.

import (
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handlePortalChangePassword(w http.ResponseWriter, r *http.Request) {
	subject, ok := s.subjectFromSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	user := s.userBySubject(subject)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	current := r.Form.Get("current_password")
	newPassword := r.Form.Get("new_password")

	if user.PasswordHash != "" && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(current)) != nil {
		http.Redirect(w, r, "/portal?error=wrong_password#security", http.StatusFound)
		return
	}
	if len(newPassword) < 8 {
		http.Redirect(w, r, "/portal?error=weak_password#security", http.StatusFound)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "could not hash password", http.StatusInternalServerError)
		return
	}
	if err := s.store.UpdatePasswordHash(user.Username, string(hash)); err != nil {
		http.Error(w, "could not update password", http.StatusInternalServerError)
		return
	}
	s.store.Audit("password_changed", subject, "", clientIP(r), "self-service")
	http.Redirect(w, r, "/portal?ok=password#security", http.StatusFound)
}

func (s *Server) handlePortalRevokeGrant(w http.ResponseWriter, r *http.Request) {
	subject, ok := s.subjectFromSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	clientID := r.Form.Get("client_id")
	if err := s.store.DeleteGrant(subject, clientID); err != nil {
		http.Error(w, "could not revoke grant", http.StatusInternalServerError)
		return
	}
	s.store.Audit("grant_revoked", subject, clientID, clientIP(r), "self-service")
	http.Redirect(w, r, "/portal#grants", http.StatusFound)
}

func (s *Server) handlePortalRevokeSession(w http.ResponseWriter, r *http.Request) {
	subject, ok := s.subjectFromSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sessionID := r.Form.Get("session_id")
	if err := s.store.DeleteSessionForSubject(subject, sessionID); err != nil {
		http.Error(w, "could not revoke session", http.StatusInternalServerError)
		return
	}
	s.store.Audit("session_revoked", subject, "", clientIP(r), "self-service")
	// If the caller just revoked their own current session, clear the cookie too.
	if cookie, err := r.Cookie(sessionCookie); err == nil && cookie.Value == sessionID {
		s.endSession(w, r)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/portal#sessions", http.StatusFound)
}

func (s *Server) handlePortalUnlinkIdentity(w http.ResponseWriter, r *http.Request) {
	subject, ok := s.subjectFromSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	user := s.userBySubject(subject)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	identityID, err := strconv.ParseInt(r.Form.Get("identity_id"), 10, 64)
	if err != nil {
		http.Redirect(w, r, "/portal?error=bad_id#identities", http.StatusFound)
		return
	}

	// Don't let a user lock themselves out: refuse to remove the last
	// identity when there is also no password set.
	if user.PasswordHash == "" {
		count, err := s.store.CountIdentities(user.ID)
		if err == nil && count <= 1 {
			http.Redirect(w, r, "/portal?error=last_identity#identities", http.StatusFound)
			return
		}
	}
	if err := s.store.UnlinkIdentity(user.ID, identityID); err != nil {
		http.Error(w, "could not unlink identity", http.StatusInternalServerError)
		return
	}
	s.store.Audit("identity_unlinked", subject, "", clientIP(r), "self-service")
	http.Redirect(w, r, "/portal#identities", http.StatusFound)
}

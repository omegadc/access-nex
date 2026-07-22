package server

// TOTP (RFC 6238) two-factor auth: enrollment (from the portal, while
// logged in) and the second login step (from /authorize and /login) once
// enabled. Rendering (the QR code page, the challenge form) is the Python
// frontend's job now — see docs/FRONTEND.md and GET /api/v1/totp in
// page_support.go — this file only validates codes and mutates state.

import (
	"encoding/base64"
	"net/http"

	"github.com/skip2/go-qrcode"

	"github.com/omegadc/access-nex/internal/secrets"
)

func (s *Server) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
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
	secret, err := secrets.GenerateTOTPSecret()
	if err != nil {
		http.Error(w, "could not generate secret", http.StatusInternalServerError)
		return
	}
	if err := s.store.SetPendingTOTPSecret(user.Username, secret); err != nil {
		http.Error(w, "could not save secret", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/portal/2fa", http.StatusFound)
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
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
	if err := r.ParseForm(); err != nil || !secrets.VerifyTOTP(user.TOTPSecret, r.Form.Get("totp_code")) {
		http.Redirect(w, r, "/portal/2fa?error=invalid", http.StatusFound)
		return
	}
	if err := s.store.ConfirmTOTP(user.Username); err != nil {
		http.Error(w, "could not enable 2FA", http.StatusInternalServerError)
		return
	}
	s.store.Audit("2fa_enabled", subject, "", clientIP(r), "")
	http.Redirect(w, r, "/portal/2fa", http.StatusFound)
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
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
	if err := r.ParseForm(); err != nil || !secrets.VerifyTOTP(user.TOTPSecret, r.Form.Get("totp_code")) {
		http.Redirect(w, r, "/portal/2fa?error=invalid", http.StatusFound)
		return
	}
	if err := s.store.DisableTOTP(user.Username); err != nil {
		http.Error(w, "could not disable 2FA", http.StatusInternalServerError)
		return
	}
	s.store.Audit("2fa_disabled", subject, "", clientIP(r), "")
	http.Redirect(w, r, "/portal/2fa", http.StatusFound)
}

// qrDataURI renders text as a PNG QR code and returns it as a data: URI
// ready to drop straight into an <img src="...">. Used by GET /api/v1/totp.
func qrDataURI(text string) (string, error) {
	png, err := qrcode.Encode(text, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

package server

// Password reset ("forgot password") and email verification. Both are
// single-use, expiring-token flows: a link is emailed, following it proves
// control of the mailbox. To avoid leaking which addresses have accounts,
// the forgot-password endpoint always returns the same response regardless
// of whether the address matched a user.
//
// Rendering (the request-a-link form, the "check your email" message, the
// choose-a-new-password form) is the Python frontend's job now — see
// docs/FRONTEND.md — this file only validates input, mutates state, and
// redirects to whichever frontend page should be shown next.

import (
	"net/http"
	"net/url"

	"golang.org/x/crypto/bcrypt"

	"github.com/omegadc/access-nex/internal/secrets"
)

// ── Forgot password ────────────────────────────────────────────────────────────

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := r.Form.Get("email")
	// GetSoleUserByEmail also protects against resetting an ambiguous
	// address shared by more than one account.
	if u, err := s.store.GetSoleUserByEmail(email); err == nil && u.PasswordHash != "" {
		token := secrets.RandomToken(32)
		if err := s.store.SavePasswordReset(token, u.Subject); err == nil {
			link := s.issuer + "/reset-password?token=" + token
			body := "Someone (hopefully you) requested a password reset for your Access-Nex account.\n\n" +
				"Reset your password: " + link + "\n\nThis link expires in 1 hour. If you didn't request this, ignore this email.\n"
			if err := s.mailer.Send(u.Email, "Reset your Access-Nex password", body); err != nil {
				s.log.Error("send password reset email", "error", err)
			}
			s.store.Audit("password_reset_requested", u.Subject, "", clientIP(r), "")
		}
	}
	redirectToMessage(w, r, "Check your email", "If that address has an account, we've sent a link to reset your password.")
}

// ── Reset password (token from the emailed link) ──────────────────────────────

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := r.Form.Get("token")
	newPassword := r.Form.Get("new_password")
	subject, err := s.store.ConsumePasswordReset(token)
	if err != nil {
		redirectToMessage(w, r, "Link expired", "That password reset link is invalid or has expired. Request a new one from the sign-in page.")
		return
	}
	if len(newPassword) < 8 {
		http.Redirect(w, r, "/reset-password?token="+url.QueryEscape(token)+"&error="+url.QueryEscape("Password must be at least 8 characters"), http.StatusFound)
		return
	}
	user := s.userBySubject(subject)
	if user == nil {
		redirectToMessage(w, r, "Account not found", "This account no longer exists.")
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
	s.store.Audit("password_reset_completed", subject, "", clientIP(r), "")
	redirectToMessage(w, r, "Password changed", "Your password has been reset. You can now sign in with your new password.")
}

// ── Email verification ────────────────────────────────────────────────────────

// sendVerificationEmail issues a token and emails the confirmation link. It
// is called both right after a user is created (CLI/admin) and from the
// portal's "resend" action.
func (s *Server) sendVerificationEmail(subject, toEmail, username string) error {
	token := secrets.RandomToken(32)
	if err := s.store.SaveEmailVerification(token, subject); err != nil {
		return err
	}
	link := s.issuer + "/verify-email?token=" + token
	body := "Welcome to Access-Nex, " + username + ".\n\nConfirm your email address: " + link +
		"\n\nThis link expires in 24 hours.\n"
	return s.mailer.Send(toEmail, "Verify your Access-Nex email address", body)
}

func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	subject, err := s.store.ConsumeEmailVerification(token)
	if err != nil {
		redirectToMessage(w, r, "Link expired", "That verification link is invalid or has expired.")
		return
	}
	if err := s.store.SetEmailVerified(subject, true); err != nil {
		http.Error(w, "could not verify email", http.StatusInternalServerError)
		return
	}
	s.store.Audit("email_verified", subject, "", clientIP(r), "")
	redirectToMessage(w, r, "Email verified", "Your email address has been confirmed.")
}

func (s *Server) handlePortalResendVerification(w http.ResponseWriter, r *http.Request) {
	subject, ok := s.subjectFromSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	user := s.userBySubject(subject)
	if user == nil || user.Email == "" {
		http.Redirect(w, r, "/portal", http.StatusFound)
		return
	}
	if err := s.sendVerificationEmail(subject, user.Email, user.Username); err != nil {
		s.log.Error("send verification email", "error", err)
	}
	http.Redirect(w, r, "/portal?ok=verification_sent#security", http.StatusFound)
}

// redirectToMessage sends the browser to the frontend's generic message
// page (used for "check your email", "link expired", "password changed",
// and similar one-off confirmations that don't need their own template).
func redirectToMessage(w http.ResponseWriter, r *http.Request, title, body string) {
	v := url.Values{}
	v.Set("title", title)
	v.Set("body", body)
	http.Redirect(w, r, "/message?"+v.Encode(), http.StatusFound)
}

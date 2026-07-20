package server

// Password reset ("forgot password") and email verification. Both are
// single-use, expiring-token flows: a link is emailed, following it proves
// control of the mailbox. To avoid leaking which addresses have accounts,
// the forgot-password endpoint always returns the same response regardless
// of whether the address matched a user.

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/omegadc/access-nex/internal/secrets"
)

// ── Forgot password ────────────────────────────────────────────────────────────

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
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
		s.renderMessagePage(w, "Check your email", "If that address has an account, we've sent a link to reset your password.")
		return
	}
	s.renderForgotPasswordPage(w, "")
}

func (s *Server) renderForgotPasswordPage(w http.ResponseWriter, errMsg string) {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="error">` + esc(errMsg) + `</div>`
	}
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Forgot Password — Access-Nex</title>` + loginStyle + `</head><body>
<div class="card">
  <div class="logo">🔐 Access-Nex</div><div class="sub">Password Reset</div>` + errHTML + `
  <h1>Forgot your password?</h1>
  <p class="hint">Enter your account email and we'll send you a reset link.</p>
  <form method="POST" action="/forgot-password">
    <label for="e">Email</label>
    <input type="email" id="e" name="email" autocomplete="email" required autofocus>
    <button type="submit">Send Reset Link</button>
  </form>
  <div class="footer"><a href="/login">← Back to sign in</a></div>
</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

// ── Reset password (token from the emailed link) ──────────────────────────────

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		token := r.Form.Get("token")
		newPassword := r.Form.Get("new_password")
		subject, err := s.store.ConsumePasswordReset(token)
		if err != nil {
			s.renderMessagePage(w, "Link expired", "That password reset link is invalid or has expired. Request a new one from the sign-in page.")
			return
		}
		if len(newPassword) < 8 {
			s.renderResetPasswordPage(w, token, "Password must be at least 8 characters")
			return
		}
		user := s.userBySubject(subject)
		if user == nil {
			s.renderMessagePage(w, "Account not found", "This account no longer exists.")
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
		s.renderMessagePage(w, "Password changed", "Your password has been reset. You can now sign in with your new password.")
		return
	}
	token := r.URL.Query().Get("token")
	s.renderResetPasswordPage(w, token, "")
}

func (s *Server) renderResetPasswordPage(w http.ResponseWriter, token, errMsg string) {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="error">` + esc(errMsg) + `</div>`
	}
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Reset Password — Access-Nex</title>` + loginStyle + `</head><body>
<div class="card">
  <div class="logo">🔐 Access-Nex</div><div class="sub">Password Reset</div>` + errHTML + `
  <h1>Choose a new password</h1>
  <form method="POST" action="/reset-password">
    <input type="hidden" name="token" value="` + esc(token) + `">
    <label for="p">New Password</label>
    <input type="password" id="p" name="new_password" autocomplete="new-password" minlength="8" required autofocus>
    <button type="submit">Reset Password</button>
  </form>
  <div class="footer"><a href="/login">← Back to sign in</a></div>
</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
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
		s.renderMessagePage(w, "Link expired", "That verification link is invalid or has expired.")
		return
	}
	if err := s.store.SetEmailVerified(subject, true); err != nil {
		http.Error(w, "could not verify email", http.StatusInternalServerError)
		return
	}
	s.store.Audit("email_verified", subject, "", clientIP(r), "")
	s.renderMessagePage(w, "Email verified", "Your email address has been confirmed.")
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

// ── Shared generic message page ───────────────────────────────────────────────

func (s *Server) renderMessagePage(w http.ResponseWriter, title, body string) {
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>` + esc(title) + ` — Access-Nex</title>` + loginStyle + `</head><body>
<div class="card">
  <div class="logo">🔐 Access-Nex</div>
  <h1>` + esc(title) + `</h1>
  <p class="hint">` + esc(body) + `</p>
  <div class="footer"><a href="/login">← Back to sign in</a></div>
</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

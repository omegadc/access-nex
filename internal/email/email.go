// Package email sends transactional mail (password resets, verification
// links). Two backends: real SMTP, or a dev-mode logger that writes the
// message to a file instead of a mail server — so the server runs and the
// flows are fully testable without any mail infrastructure configured.
package email

import (
	"fmt"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Mailer sends a single plain-text email.
type Mailer interface {
	Send(to, subject, body string) error
}

// Config holds SMTP connection details. A zero-value Config (empty Host)
// means "no SMTP configured" — New returns a LogMailer in that case.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// New returns an SMTPMailer if cfg.Host is set, otherwise a LogMailer that
// writes outgoing mail to outboxDir/outbox.log for local/dev use.
func New(cfg Config, outboxDir string) Mailer {
	if cfg.Host == "" {
		return &LogMailer{path: filepath.Join(outboxDir, "outbox.log")}
	}
	if cfg.From == "" {
		cfg.From = "access-nex@localhost"
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	return &SMTPMailer{cfg: cfg}
}

// SMTPMailer sends mail over SMTP with PLAIN auth (STARTTLS is handled by
// net/smtp.SendMail automatically when the server advertises it).
type SMTPMailer struct{ cfg Config }

func (m *SMTPMailer) Send(to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	var auth smtp.Auth
	if m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		m.cfg.From, to, subject, body)
	return smtp.SendMail(addr, auth, m.cfg.From, []string{to}, []byte(msg))
}

// LogMailer appends outgoing mail to a local file instead of sending it —
// the dev-mode fallback when no SMTP server is configured. Password reset
// and verification links still work end-to-end; an operator just reads the
// link out of the file instead of an inbox.
type LogMailer struct{ path string }

func (m *LogMailer) Send(to, subject, body string) error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(m.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	sep := strings.Repeat("-", 60)
	_, err = fmt.Fprintf(f, "%s\n[%s] To: %s\nSubject: %s\n\n%s\n%s\n\n",
		sep, time.Now().Format(time.RFC3339), to, subject, body, sep)
	return err
}

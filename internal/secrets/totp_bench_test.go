package secrets

import (
	"testing"
	"time"
)

// BenchmarkTOTPAt measures a single HOTP/SHA1 code computation — runs once
// per code on the enrollment QR/display path.
func BenchmarkTOTPAt(b *testing.B) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := TOTPAt(secret, now); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyTOTP measures the full 2FA check on every password+TOTP
// login: it recomputes the code for up to 3 time steps (±30s skew window).
func BenchmarkVerifyTOTP(b *testing.B) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		b.Fatal(err)
	}
	code, err := TOTPAt(secret, time.Now())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		VerifyTOTP(secret, code)
	}
}

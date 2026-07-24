package secrets

import (
	"testing"
)

// BenchmarkBoxEncrypt measures AES-256-GCM sealing of a provider client
// secret — runs once per `provider add`/`provider update` and once per
// /oauth/callback (to decrypt, see BenchmarkBoxDecrypt), so it's on the
// external-login hot path.
func BenchmarkBoxEncrypt(b *testing.B) {
	box := newTestBox(b)
	plaintext := "super-secret-oauth-client-secret-value"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := box.Encrypt(plaintext); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBoxDecrypt measures the AES-256-GCM open on every external-provider
// token exchange (internal/server/proxy.go decrypts the stored client secret
// on every /oauth/callback).
func BenchmarkBoxDecrypt(b *testing.B) {
	box := newTestBox(b)
	encoded, err := box.Encrypt("super-secret-oauth-client-secret-value")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := box.Decrypt(encoded); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRandomToken covers the sizes actually used in the codebase:
// auth codes (32 bytes), proxy state (24 bytes), and session IDs.
func BenchmarkRandomToken(b *testing.B) {
	for _, size := range []int{16, 24, 32} {
		b.Run(sizeLabel(size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				RandomToken(size)
			}
		})
	}
}

func sizeLabel(n int) string {
	switch n {
	case 16:
		return "16B"
	case 24:
		return "24B"
	case 32:
		return "32B"
	default:
		return "N"
	}
}

func newTestBox(b *testing.B) *Box {
	b.Helper()
	box, err := NewBox(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	return box
}

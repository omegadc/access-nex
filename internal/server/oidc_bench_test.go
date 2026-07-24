package server

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/omegadc/access-nex/internal/secrets"
)

func benchServer(b *testing.B) *Server {
	b.Helper()
	key, err := secrets.GenerateRSAKey()
	if err != nil {
		b.Fatal(err)
	}
	return &Server{
		issuer: "https://access-nex.bench",
		keys:   []SigningKey{{Kid: "bench-key", Key: key}},
	}
}

// BenchmarkSignJWT measures RS256 signing (SHA-256 digest + RSA-2048
// PKCS1v15) — every /token response signs both an access token and an
// id_token, so this cost is paid twice per login and once per refresh.
func BenchmarkSignJWT(b *testing.B) {
	s := benchServer(b)
	claims := map[string]any{
		"iss": s.issuer, "sub": "user-1", "aud": "client-bench",
		"scope": "openid profile email", "exp": int64(4102444800), "iat": int64(0),
		"jti": "bench-jti", "token_use": "access",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := s.signJWT(claims); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBcryptCompareHashAndPassword measures the cost paid on every
// local-account login and password change (server.go, apiv1.go, reset.go all
// call this at bcrypt.DefaultCost).
func BenchmarkBcryptCompareHashAndPassword(b *testing.B) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-horse-battery-staple"), bcrypt.DefaultCost)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := bcrypt.CompareHashAndPassword(hash, []byte("correct-horse-battery-staple")); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBcryptGenerateFromPassword measures account creation / password
// reset cost at the same DefaultCost used in production.
func BenchmarkBcryptGenerateFromPassword(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := bcrypt.GenerateFromPassword([]byte("correct-horse-battery-staple"), bcrypt.DefaultCost); err != nil {
			b.Fatal(err)
		}
	}
}

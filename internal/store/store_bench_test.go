package store_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/omegadc/access-nex/internal/database"
	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/store"
)

// newBenchStore opens a fresh SQLite-backed store (real schema, real
// migrations) in a temp dir, so these benchmarks measure actual query/driver
// cost rather than a mock.
func newBenchStore(b *testing.B) *store.Store {
	b.Helper()
	db, err := database.Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { db.Close() })
	return store.New(db)
}

// BenchmarkCreateUser measures the write side of every `user add` and every
// first-time external-provider login (provisionExternalUser).
func BenchmarkCreateUser(b *testing.B) {
	st := newBenchStore(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		u := &models.User{
			Subject:  fmt.Sprintf("user-%d", i),
			Username: fmt.Sprintf("user%d", i),
			Email:    fmt.Sprintf("user%d@example.com", i),
			Name:     "Bench User",
		}
		if err := st.CreateUser(u); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetUserByUsername measures the lookup on every local-login POST
// to /authorize.
func BenchmarkGetUserByUsername(b *testing.B) {
	st := newBenchStore(b)
	if err := st.CreateUser(&models.User{
		Subject: "user-1", Username: "alice", Email: "alice@example.com", Name: "Alice",
	}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := st.GetUserByUsername("alice"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetUserBySubject measures the lookup done for every /userinfo and
// every id_token claims fill-in (userBySubject in oidc.go).
func BenchmarkGetUserBySubject(b *testing.B) {
	st := newBenchStore(b)
	if err := st.CreateUser(&models.User{
		Subject: "user-1", Username: "alice", Email: "alice@example.com", Name: "Alice",
	}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := st.GetUserBySubject("user-1"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuthCodeRoundTrip measures a full authorization-code lifecycle
// (save at /authorize, consume at /token) — every code grant does exactly
// one of these.
func BenchmarkAuthCodeRoundTrip(b *testing.B) {
	st := newBenchStore(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		code := fmt.Sprintf("code-%d", i)
		err := st.SaveAuthCode(&models.AuthCode{
			Code:        code,
			ClientID:    "client-bench",
			RedirectURI: "https://example.com/callback",
			Subject:     "user-1",
			Scope:       []string{"openid", "profile", "email"},
			ExpiresAt:   time.Now().Add(5 * time.Minute),
			AuthTime:    time.Now(),
		})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := st.ConsumeAuthCode(code); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSaveAccessToken measures the write that happens once per issued
// access token (every /token response and every refresh grant).
func BenchmarkSaveAccessToken(b *testing.B) {
	st := newBenchStore(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		err := st.SaveAccessToken(&models.TokenRecord{
			Token:     fmt.Sprintf("token-%d", i),
			JTI:       fmt.Sprintf("jti-%d", i),
			ClientID:  "client-bench",
			Subject:   "user-1",
			Scope:     []string{"openid", "profile", "email"},
			ExpiresAt: time.Now().Add(time.Hour),
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// newBenchProvider registers a real provider row — users.provider_id and
// identities.provider_id are foreign keys, so EnsureExternalUser needs one
// to actually exist rather than a made-up ID.
func newBenchProvider(b *testing.B, st *store.Store) string {
	b.Helper()
	p := &models.Provider{
		ID:             "provider-google-bench",
		Name:           "Google",
		Kind:           models.ProviderKindOIDC,
		ClientID:       "bench-client-id",
		UserIdentifier: "sub",
		Scopes:         []string{"openid", "profile", "email"},
		Enabled:        true,
	}
	if err := st.CreateProvider(p); err != nil {
		b.Fatal(err)
	}
	return p.ID
}

// BenchmarkEnsureExternalUser_NewUser measures a first-time external login:
// no existing identity, no email match — hits the create-user path.
func BenchmarkEnsureExternalUser_NewUser(b *testing.B) {
	st := newBenchStore(b)
	providerID := newBenchProvider(b, st)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		externalID := fmt.Sprintf("ext-%d", i)
		_, _, _, err := st.EnsureExternalUser(providerID, externalID, "", "", "Bench User", false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEnsureExternalUser_ExistingIdentity measures every subsequent
// external login for the same account — the common case once a user has
// signed in via a provider before.
func BenchmarkEnsureExternalUser_ExistingIdentity(b *testing.B) {
	st := newBenchStore(b)
	providerID := newBenchProvider(b, st)
	if _, _, _, err := st.EnsureExternalUser(providerID, "ext-1", "", "", "Bench User", false); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := st.EnsureExternalUser(providerID, "ext-1", "", "", "Bench User", false); err != nil {
			b.Fatal(err)
		}
	}
}

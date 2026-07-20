package server

// DPoP (RFC 9449): sender-constrained access tokens. A client proves
// possession of a private key on every request by attaching a signed
// "DPoP proof" JWT; the server binds the issued token to that key's JWK
// thumbprint (the `cnf.jkt` claim) and later requires a matching proof to
// use the token, defeating token theft/replay by anyone who doesn't hold
// the private key.
//
// This implements the ES256/RS256 subset needed for real-world clients
// (Go, JS, and Python DPoP libraries default to ES256 on the P-256 curve)
// without a JOSE dependency: proofs are three base64url segments we parse
// and verify against stdlib crypto directly.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/omegadc/access-nex/internal/secrets"
)

const dpopProofMaxAge = 5 * time.Minute

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type dpopHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	JWK jwk    `json:"jwk"`
}

type dpopClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	Ath   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// errDPoPNonceRequired signals that the server requires (RFC 9449 §8) a
// server-issued nonce in the proof and the presented proof either had none
// or had a stale/already-used one. Callers respond 400 use_dpop_nonce with
// a freshly issued nonce in the DPoP-Nonce header, rather than a bare
// invalid_dpop_proof — the client is expected to retry once, not give up.
var errDPoPNonceRequired = errors.New("dpop nonce required")

// thumbprint computes the RFC 7638 JWK thumbprint: SHA-256 over the JSON
// object of *required* members only, keys in lexicographic order, no
// whitespace — so it must be built by hand rather than via json.Marshal.
func (k jwk) thumbprint() (string, error) {
	var canonical string
	switch k.Kty {
	case "EC":
		if k.Crv == "" || k.X == "" || k.Y == "" {
			return "", errors.New("incomplete EC JWK")
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Crv, k.X, k.Y)
	case "RSA":
		if k.N == "" || k.E == "" {
			return "", errors.New("incomplete RSA JWK")
		}
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N)
	default:
		return "", fmt.Errorf("unsupported JWK kty %q", k.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		eInt := 0
		for _, b := range e {
			eInt = eInt<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: eInt}, nil
	default:
		return nil, fmt.Errorf("unsupported JWK kty %q", k.Kty)
	}
}

// verifyDPoPProof validates the `DPoP` request header against the expected
// HTTP method/URL, checks freshness and replay, and returns the JWK
// thumbprint the caller proved possession of.
func (s *Server) verifyDPoPProof(proof, method, url string) (jkt string, err error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed proof")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("invalid header encoding")
	}
	var header dpopHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", errors.New("invalid header JSON")
	}
	if header.Typ != "dpop+jwt" {
		return "", errors.New(`typ must be "dpop+jwt"`)
	}

	pub, err := header.JWK.publicKey()
	if err != nil {
		return "", err
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errors.New("invalid signature encoding")
	}

	switch header.Alg {
	case "ES256":
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return "", errors.New("alg/key mismatch")
		}
		r := new(big.Int).SetBytes(sig[:32])
		sVal := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(ecKey, digest[:], r, sVal) {
			return "", errors.New("invalid signature")
		}
	case "RS256":
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return "", errors.New("alg/key mismatch")
		}
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], sig); err != nil {
			return "", errors.New("invalid signature")
		}
	default:
		return "", fmt.Errorf("unsupported alg %q", header.Alg)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid claims encoding")
	}
	var claims dpopClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return "", errors.New("invalid claims JSON")
	}
	if claims.HTM != method {
		return "", errors.New("htm mismatch")
	}
	if stripQuery(claims.HTU) != stripQuery(url) {
		return "", errors.New("htu mismatch")
	}
	age := time.Since(time.Unix(claims.IAT, 0))
	if age < -30*time.Second || age > dpopProofMaxAge {
		return "", errors.New("proof is not fresh")
	}
	if claims.JTI == "" || s.dpopJTISeen(claims.JTI) {
		return "", errors.New("proof jti missing or replayed")
	}
	if s.requireDPoPNonce {
		if claims.Nonce == "" || !s.consumeDPoPNonce(claims.Nonce) {
			return "", errDPoPNonceRequired
		}
	}

	return header.JWK.thumbprint()
}

func stripQuery(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}

// dpopJTISeen records a proof jti and reports whether it was already used
// (replay). Entries are pruned opportunistically; a proof's freshness window
// is only dpopProofMaxAge, so the cache never needs to grow unbounded.
func (s *Server) dpopJTISeen(jti string) bool {
	s.dpopMu.Lock()
	defer s.dpopMu.Unlock()
	if _, ok := s.dpopSeen[jti]; ok {
		return true
	}
	cutoff := time.Now().Add(-2 * dpopProofMaxAge)
	if len(s.dpopSeen) > 5000 {
		for k, t := range s.dpopSeen {
			if t.Before(cutoff) {
				delete(s.dpopSeen, k)
			}
		}
	}
	s.dpopSeen[jti] = time.Now()
	return false
}

// issueDPoPNonce mints a single-use nonce for a client to embed in its next
// DPoP proof, per the RFC 9449 §8 challenge/response mechanism.
func (s *Server) issueDPoPNonce() string {
	nonce := secrets.RandomToken(24)
	s.dpopMu.Lock()
	if len(s.dpopNonces) > 5000 {
		now := time.Now()
		for k, exp := range s.dpopNonces {
			if now.After(exp) {
				delete(s.dpopNonces, k)
			}
		}
	}
	s.dpopNonces[nonce] = time.Now().Add(dpopProofMaxAge)
	s.dpopMu.Unlock()
	return nonce
}

// consumeDPoPNonce validates and invalidates a nonce in one step (single-use).
func (s *Server) consumeDPoPNonce(nonce string) bool {
	s.dpopMu.Lock()
	defer s.dpopMu.Unlock()
	expires, ok := s.dpopNonces[nonce]
	if !ok {
		return false
	}
	delete(s.dpopNonces, nonce)
	return time.Now().Before(expires)
}

// dpopProofFromRequest validates the request's DPoP header, if present,
// against its own method+URL and returns the resulting jkt (empty if the
// client didn't send one — a normal Bearer-token request). When the server
// requires a nonce and none/an invalid one was presented, it writes the
// RFC 9449 §8 challenge response itself (400 use_dpop_nonce + a fresh
// DPoP-Nonce header) and the caller should stop processing the request.
func (s *Server) dpopProofFromRequest(w http.ResponseWriter, r *http.Request) (jkt string, headerErr string, challenged bool) {
	proof := r.Header.Get("DPoP")
	if proof == "" {
		return "", "", false
	}
	full := s.endpoint(r.URL.Path)
	jkt, err := s.verifyDPoPProof(proof, r.Method, full)
	if err != nil {
		if errors.Is(err, errDPoPNonceRequired) {
			s.metrics.dpopRejections.WithLabelValues("nonce_required").Inc()
			w.Header().Set("DPoP-Nonce", s.issueDPoPNonce())
			writeOAuthError(w, http.StatusBadRequest, "use_dpop_nonce", "Retry with the nonce from the DPoP-Nonce response header")
			return "", "", true
		}
		// A fixed label, not err.Error(): several of verifyDPoPProof's error
		// messages interpolate attacker-controlled fields (e.g. the proof's
		// own "alg"), and an unbounded label value on an unauthenticated
		// endpoint is a cardinality/memory-exhaustion vector.
		s.metrics.dpopRejections.WithLabelValues("invalid_proof").Inc()
		return "", err.Error(), false
	}
	if s.requireDPoPNonce {
		// Hand the client a nonce for its *next* request now, so a well-behaved
		// client only ever pays the challenge round trip once per key.
		w.Header().Set("DPoP-Nonce", s.issueDPoPNonce())
	}
	return jkt, "", false
}

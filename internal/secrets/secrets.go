// Package secrets handles encryption of stored provider client secrets
// (AES-256-GCM with a key file generated on first use) and persistence of
// the RSA key used to sign JWTs, so tokens stay valid across restarts.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	keyFileName     = "secret.key"  // 32-byte AES key, base64
	signingFileName = "signing.pem" // RSA private key, PKCS#1 PEM
)

// Box encrypts and decrypts small secrets with AES-256-GCM.
type Box struct {
	aead cipher.AEAD
}

// NewBox loads the AES key from configDir/secret.key, generating it on first
// use. The file is created with owner-only permissions.
func NewBox(configDir string) (*Box, error) {
	path := filepath.Join(configDir, keyFileName)
	var key []byte

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("invalid key file %s", path)
		}
	case os.IsNotExist(err):
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
			return nil, fmt.Errorf("write key file: %w", err)
		}
	default:
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Encrypt returns base64(nonce || ciphertext).
func (b *Box) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := b.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt.
func (b *Box) Decrypt(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(raw) < b.aead.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:b.aead.NonceSize()], raw[b.aead.NonceSize():]
	plain, err := b.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// LoadOrCreateSigningKey returns the RSA key stored at configDir/signing.pem,
// generating a 2048-bit key on first use.
func LoadOrCreateSigningKey(configDir string) (*rsa.PrivateKey, error) {
	path := filepath.Join(configDir, signingFileName)

	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM in %s", path)
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write signing key: %w", err)
	}
	return key, nil
}

// GenerateRSAKey creates a new 2048-bit signing key.
func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// EncodePrivateKeyPEM serializes an RSA key as PKCS#1 PEM text.
func EncodePrivateKeyPEM(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

// ParsePrivateKeyPEM reverses EncodePrivateKeyPEM.
func ParsePrivateKeyPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ParsePublicKeyPEM parses an RSA public key in PKIX ("PUBLIC KEY") or
// PKCS#1 ("RSA PUBLIC KEY") PEM form.
func ParsePublicKeyPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, errors.New("not an RSA public key")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

// RandomToken returns a URL-safe random string of size random bytes.
func RandomToken(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

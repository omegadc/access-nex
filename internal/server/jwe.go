package server

// Compact JWE serialization for ID-token encryption:
// alg RSA-OAEP-256 (key wrap) + enc A256GCM (content encryption).
// Produced when an application has an id_token_enc_key registered.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
)

// encryptJWE wraps payload (a signed JWT) in a five-part compact JWE using
// the recipient's RSA public key.
func encryptJWE(pub *rsa.PublicKey, payload string) (string, error) {
	header := map[string]string{
		"alg": "RSA-OAEP-256",
		"enc": "A256GCM",
		"cty": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	protected := b64(headerJSON)

	// Content encryption key, wrapped for the recipient.
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		return "", err
	}
	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, cek, nil)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aead.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	// Per RFC 7516 the AAD is the ASCII bytes of the protected header.
	sealed := aead.Seal(nil, iv, []byte(payload), []byte(protected))
	ciphertext := sealed[:len(sealed)-16]
	tag := sealed[len(sealed)-16:]

	return protected + "." + b64(wrappedKey) + "." + b64(iv) + "." + b64(ciphertext) + "." + b64(tag), nil
}

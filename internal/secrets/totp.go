package secrets

// RFC 6238 TOTP (the algorithm behind Google Authenticator / Authy / 1Password
// TOTP codes): HMAC-SHA1 over a 30-second time counter, truncated to 6 digits.
// Implemented directly against stdlib crypto so 2FA doesn't pull in a third
// dependency for ~80 lines of well-specified math.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpDigits = 6
	totpStep   = 30 * time.Second
)

// GenerateTOTPSecret returns a random base32 secret (no padding), suitable
// for both code generation and display/QR enrollment.
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20) // 160 bits, the RFC 4226 recommended HOTP secret length
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// TOTPAt computes the 6-digit code for secret at time t.
func TOTPAt(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret: %w", err)
	}
	counter := uint64(t.Unix() / int64(totpStep.Seconds()))
	return hotp(key, counter), nil
}

func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	for i := 7; i >= 0; i-- {
		buf[i] = byte(counter & 0xff)
		counter >>= 8
	}
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, code%mod)
}

// VerifyTOTP checks code against secret, allowing ±1 step (30s) of clock skew.
func VerifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	now := time.Now()
	for _, skew := range []time.Duration{0, -totpStep, totpStep} {
		want, err := TOTPAt(secret, now.Add(skew))
		if err == nil && hmac.Equal([]byte(want), []byte(code)) {
			return true
		}
	}
	return false
}

// TOTPAuthURL builds the otpauth:// URL that authenticator apps scan as a QR
// code to enroll the secret.
func TOTPAuthURL(issuer, accountName, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(accountName)
	q := url.Values{
		"secret": {secret},
		"issuer": {issuer},
		"digits": {fmt.Sprint(totpDigits)},
		"period": {fmt.Sprint(int(totpStep.Seconds()))},
	}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

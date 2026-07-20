package secrets

// Self-signed certificate generation for `server --tls-self-signed` — a
// zero-config way to get HTTPS (and therefore Secure cookies) for local/dev
// use without a reverse proxy. For real deployments pass --tls-cert/--tls-key
// with a certificate from a real CA (or a proxy in front of access-nex).

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// GenerateSelfSignedCert creates an in-memory RSA certificate valid for the
// given hosts/IPs (e.g. "localhost", "127.0.0.1"), for immediate use in a
// tls.Config. Nothing is written to disk.
func GenerateSelfSignedCert(hosts []string) (tls.Certificate, error) {
	key, err := GenerateRSAKey()
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"access-nex (self-signed)"}, CommonName: "access-nex"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(825 * 24 * time.Hour), // under the 825-day CA/Browser Forum cap
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed leaf acting as its own root
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

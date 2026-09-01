package certutil

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2026 Aaron Turner  <synfinatic at gmail dot com>
 *
 * This program is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or with the authors permission any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// CAValidity is how long a generated CA is valid for.  The CA private key is
// retained in the SecureStore and reused across leaf rotations, so it is
// long-lived on purpose: the user only has to repeat the OS/runtime trust
// steps if the CA itself actually expires.
const CAValidity = 10 * 365 * 24 * time.Hour

// LeafValidity is intentionally short: rotating the leaf is cheap (just
// `setup ecs ssl --self-signed` again, reusing the existing CA) and never
// requires re-trusting anything, so there's no reason to make it long-lived.
const LeafValidity = 30 * 24 * time.Hour

// CACommonName identifies the generated CA in OS trust-store UIs so users
// can find (and remove) it later.
const CACommonName = "aws-sso-cli ECS Server CA"

// LeafCommonName is kept for readability/logs; SANs (not the CN) are what
// TLS clients actually validate against.
const LeafCommonName = "localhost"

// DefaultDNSNames are always included in a generated leaf certificate.
var DefaultDNSNames = []string{"localhost"}

// DefaultIPs are always included in a generated leaf certificate.
// 169.254.170.2 is the well-known ECS credentials endpoint IP used by the
// `aws-sso ecs docker` / Docker Compose flow, so the default leaf covers
// that path too.
var DefaultIPs = []net.IP{
	net.ParseIP("127.0.0.1"),
	net.ParseIP("::1"),
	net.ParseIP("169.254.170.2"),
}

// KeyPair holds a PEM-encoded certificate and its PEM-encoded (PKCS#8)
// private key.  PKCS#8 is required, not just conventional: SaveEcsSslKeyPair
// and SaveEcsCaKeyPair validate keys via x509.ParsePKCS8PrivateKey and
// reject the SEC1 "EC PRIVATE KEY" form.
type KeyPair struct {
	CertPEM string
	KeyPEM  string
}

// GenerateCA creates a new self-signed CA certificate/key suitable for
// signing ECS Server leaf certificates via GenerateLeaf.
func GenerateCA() (KeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("unable to generate CA private key: %w", err)
	}

	serial, err := newSerialNumber()
	if err != nil {
		return KeyPair{}, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: CACommonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return KeyPair{}, fmt.Errorf("unable to create CA certificate: %w", err)
	}

	return encodeKeyPair(certDER, key)
}

// GenerateLeaf creates a new leaf certificate signed by the given CA, for
// the ECS Server to present over TLS, covering the SANs in
// DefaultDNSNames/DefaultIPs.
func GenerateLeaf(ca KeyPair) (KeyPair, error) {
	caCert, caKey, err := parseCAKeyPair(ca)
	if err != nil {
		return KeyPair{}, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("unable to generate leaf private key: %w", err)
	}

	serial, err := newSerialNumber()
	if err != nil {
		return KeyPair{}, err
	}

	dnsNames := append([]string{}, DefaultDNSNames...)
	ips := append([]net.IP{}, DefaultIPs...)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: LeafCommonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(LeafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return KeyPair{}, fmt.Errorf("unable to create leaf certificate: %w", err)
	}

	return encodeKeyPair(certDER, key)
}

// Fingerprint returns the SHA-256 fingerprint of a PEM-encoded certificate,
// colon-separated hex (the openssl/keytool display convention) so it can be
// shown to the user for visual verification of what they're trusting.
func Fingerprint(certPEM string) (string, error) {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, 0, len(sum))
	for _, b := range sum {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return strings.Join(parts, ":"), nil
}

func newSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("unable to generate certificate serial number: %w", err)
	}
	return serial, nil
}

func encodeKeyPair(certDER []byte, key *ecdsa.PrivateKey) (KeyPair, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return KeyPair{}, fmt.Errorf("unable to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return KeyPair{
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
	}, nil
}

func parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("unable to decode PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate: %w", err)
	}
	return cert, nil
}

func parseCAKeyPair(ca KeyPair) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, err := parseCertificate(ca.CertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse CA certificate: %w", err)
	}

	block, _ := pem.Decode([]byte(ca.KeyPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("unable to decode PEM CA private key")
	}
	rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse CA private key: %w", err)
	}
	key, ok := rawKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA private key is not an ECDSA key")
	}

	return cert, key, nil
}

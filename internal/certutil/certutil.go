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
	"unsafe"
)

// CAValidity is how long a generated CA is valid for.  The CA private key is
// retained in the SecureStore and reused indefinitely, so it is long-lived on
// purpose: the user only has to repeat the OS/runtime trust steps if the CA
// itself actually expires.
const CAValidity = 10 * 365 * 24 * time.Hour

// LeafValidity is intentionally short: the leaf is never persisted, it's
// minted fresh in memory from the CA every time it's needed (native `ecs
// server` startup, or `ecs docker start`/`write-config` before the container
// starts), so there's no reason to make it long-lived.
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

// permittedDNSDomains and permittedIPRanges are the X.509 name constraints
// (RFC 5280 section 4.2.1.10) burned into every generated CA.  Users are told to
// install this CA as a trust root -- the OS trust store, the JVM cacerts,
// NODE_EXTRA_CA_CERTS -- so an unconstrained CA would hand whoever holds its
// private key a universal MITM capability against every TLS connection that
// machine makes.  Constraining it means a leaked CA key can only forge
// certificates for the loopback/ECS names the ECS Server actually listens on.
//
// Both a DNS and an IP constraint must be present: under RFC 5280 a name type
// with no constraint of that type is entirely unconstrained, so permitting
// only DNS names would leave IP SANs wide open (and vice versa).  These must
// stay a superset of DefaultDNSNames/DefaultIPs or GenerateLeaf will produce
// leaves its own CA is not authorized to sign.
var permittedDNSDomains = []string{"localhost"}

var permittedIPRanges = []*net.IPNet{
	{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
	{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
	{IP: net.IPv4(169, 254, 170, 2).To4(), Mask: net.CIDRMask(32, 32)},
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

		// Marked critical so a validator that does not understand name
		// constraints rejects the CA outright rather than silently ignoring
		// the extension and treating it as unconstrained.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permittedDNSDomains,
		PermittedIPRanges:           permittedIPRanges,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return KeyPair{}, fmt.Errorf("unable to create CA certificate: %w", err)
	}

	return encodeKeyPair(certDER, key)
}

// GenerateLeaf creates a new leaf certificate signed by the given CA, for
// the ECS Server to present over TLS, using the default SANs in
// DefaultDNSNames/DefaultIPs.
func GenerateLeaf(ca KeyPair) (KeyPair, error) {
	caCert, caKey, err := parseCAKeyPair(ca)
	if err != nil {
		return KeyPair{}, err
	}
	// Best-effort defense-in-depth: the CA private key is only needed for the
	// x509.CreateCertificate call below, so wipe the parsed scalar as soon as
	// this function returns. This shrinks the exposure window but is not a
	// secure-erase guarantee -- see ZeroSecret.
	defer zeroPrivateKey(caKey)

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

// NotAfter returns the expiration time of a PEM-encoded certificate, so
// callers can warn users before a CA or leaf certificate lapses.
func NotAfter(certPEM string) (time.Time, error) {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

func newSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("unable to generate certificate serial number: %w", err)
	}
	return serial, nil
}

// zeroPrivateKey best-effort overwrites the scalar of an ECDSA private key
// once it's no longer needed. Like ZeroSecret, this is defense-in-depth, not
// a secure-erase guarantee: the runtime/GC may have already copied the
// underlying words elsewhere.
//
// Note that big.Int.SetInt64(0) is *not* sufficient: setting a big.Int to
// zero only reslices its backing word array to length zero, leaving every
// word of the secret scalar intact in memory behind it. The words have to be
// overwritten through the slice first, then the big.Int normalized back to
// zero via SetBits.
func zeroPrivateKey(key *ecdsa.PrivateKey) {
	if key == nil || key.D == nil { // nolint:staticcheck
		return
	}
	words := key.D.Bits() // nolint:staticcheck
	for i := range words {
		words[i] = 0
	}
	key.D.SetBits(words) // nolint:staticcheck
}

// ZeroSecret best-effort overwrites the backing bytes of a string in place,
// for scrubbing secret material (e.g. a CA private key PEM) from memory as
// soon as the caller is done with it. Go string copies (assignment, passing
// by value) share the same backing array rather than duplicating it, so
// zeroing through any one copy after all uses are done clears it for all of
// them.
//
// Because of that same aliasing, callers must only pass a string they
// exclusively own -- e.g. one produced by strings.Clone -- never a value
// fetched directly from a cache or struct field still in use elsewhere (a
// SecureStore's in-memory copy, a string literal). Zeroing an aliased string
// corrupts every alias, not just the caller's use of it; it also risks a
// SIGBUS/fault if the backing bytes happen to live in read-only memory
// (e.g. a compiled-in literal).
//
// This is explicitly best-effort, defense-in-depth: it shrinks how long the
// secret sits in memory we have a handle to, not a guarantee of secure
// erasure. Go's garbage collector can have relocated or copied the
// underlying bytes, and callers that received this value from elsewhere
// (e.g. a SecureStore backend's own internal buffers) may hold copies this
// function has no way to reach.
func ZeroSecret(s string) {
	if len(s) == 0 {
		return
	}
	b := unsafe.Slice(unsafe.StringData(s), len(s))
	for i := range b {
		b[i] = 0
	}
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

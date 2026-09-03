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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCA(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(ca.CertPEM))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	assert.True(t, cert.IsCA)
	assert.True(t, cert.BasicConstraintsValid)
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCertSign)
	assert.Equal(t, CACommonName, cert.Subject.CommonName)
	assert.WithinDuration(t, cert.NotBefore.Add(CAValidity), cert.NotAfter, time.Minute)

	keyBlock, _ := pem.Decode([]byte(ca.KeyPEM))
	require.NotNil(t, keyBlock)
	rawKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
	_, ok := rawKey.(*ecdsa.PrivateKey)
	assert.True(t, ok, "CA private key should be an ECDSA key")
}

func TestGenerateCA_NameConstraints(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	cert := parsePEMCert(t, ca.CertPEM)

	assert.True(t, cert.PermittedDNSDomainsCritical)
	assert.Equal(t, []string{"localhost"}, cert.PermittedDNSDomains)

	ranges := make([]string, len(cert.PermittedIPRanges))
	for i, r := range cert.PermittedIPRanges {
		ranges[i] = r.String()
	}
	assert.Contains(t, ranges, "127.0.0.1/32")
	assert.Contains(t, ranges, "::1/128")
	assert.Contains(t, ranges, "169.254.170.2/32")
	assert.Len(t, cert.PermittedIPRanges, 3)

	// No excluded subtrees: the only way to exclude a whole name form is an
	// empty subtree, which the JVM refuses to parse -- see the NOTE in
	// GenerateCA.  Asserting their absence keeps that from being "fixed" by
	// someone who hasn't read it.
	assert.Empty(t, cert.ExcludedEmailAddresses)
	assert.Empty(t, cert.ExcludedURIDomains)
}

// TestGenerateCA_ServerAuthOnly guards the CA's ExtKeyUsage, which declares the
// CA usable only for TLS server auth.  Enforcement is verifier-dependent:
// neither Go (EKU nesting checks were removed) nor OpenSSL (`verify -purpose
// codesign` still passes) honor it, but Windows CryptoAPI and the macOS
// Security framework do, so it is worth stating.  This asserts the extension is
// present rather than that any particular verifier rejects.
func TestGenerateCA_ServerAuthOnly(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	cert := parsePEMCert(t, ca.CertPEM)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, cert.ExtKeyUsage)
}

func TestGenerateLeaf_RejectsOutOfConstraintDNSSAN(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	leafCert := signLeafTemplate(t, ca, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "evil"},
		DNSNames:    []string{"evil.com"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	caCert := parsePEMCert(t, ca.CertPEM)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.Error(t, err, "leaf with an out-of-constraint DNS SAN should not verify against the CA")
}

func TestGenerateLeaf_RejectsOutOfConstraintIPSAN(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	leafCert := signLeafTemplate(t, ca, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "evil"},
		IPAddresses: []net.IP{net.ParseIP("8.8.8.8")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	caCert := parsePEMCert(t, ca.CertPEM)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.Error(t, err, "leaf with an out-of-constraint IP SAN should not verify against the CA")
}

func TestGenerateLeaf_SignedByCA(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	leaf, err := GenerateLeaf(ca)
	require.NoError(t, err)

	caCert := parsePEMCert(t, ca.CertPEM)
	leafCert := parsePEMCert(t, leaf.CertPEM)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.NoError(t, err, "leaf certificate should chain-verify against its issuing CA")
}

func TestGenerateLeaf_DefaultSANs(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	leaf, err := GenerateLeaf(ca)
	require.NoError(t, err)

	cert := parsePEMCert(t, leaf.CertPEM)

	assert.Contains(t, cert.DNSNames, "localhost")

	ips := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ips[i] = ip.String()
	}
	assert.Contains(t, ips, "127.0.0.1")
	assert.Contains(t, ips, "::1")
	assert.Contains(t, ips, "169.254.170.2")
}

func TestGenerateLeaf_UntrustedCARejected(t *testing.T) {
	t.Parallel()

	ca1, err := GenerateCA()
	require.NoError(t, err)
	ca2, err := GenerateCA()
	require.NoError(t, err)

	leaf, err := GenerateLeaf(ca1)
	require.NoError(t, err)

	leafCert := parsePEMCert(t, leaf.CertPEM)
	unrelatedCACert := parsePEMCert(t, ca2.CertPEM)

	pool := x509.NewCertPool()
	pool.AddCert(unrelatedCACert)

	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.Error(t, err, "leaf should not verify against an unrelated CA")
}

func TestFingerprint(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	fp, err := Fingerprint(ca.CertPEM)
	require.NoError(t, err)

	cert := parsePEMCert(t, ca.CertPEM)
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, 0, len(sum))
	for _, b := range sum {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	expected := strings.Join(parts, ":")

	assert.Equal(t, expected, fp)
}

func TestFingerprint_InvalidPEM(t *testing.T) {
	t.Parallel()

	_, err := Fingerprint("not a pem block")
	assert.ErrorContains(t, err, "unable to decode PEM certificate")
}

func TestFingerprint_InvalidCertificateBytes(t *testing.T) {
	t.Parallel()

	badCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a real cert")}))
	_, err := Fingerprint(badCertPEM)
	assert.ErrorContains(t, err, "unable to parse certificate")
}

func TestGenerateLeaf_InvalidCACertPEM(t *testing.T) {
	t.Parallel()

	_, err := GenerateLeaf(KeyPair{CertPEM: "not a pem block", KeyPEM: "also not a pem block"})
	assert.ErrorContains(t, err, "unable to parse CA certificate")
}

func TestGenerateLeaf_InvalidCAKeyPEM(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)
	ca.KeyPEM = "not a pem block"

	_, err = GenerateLeaf(ca)
	assert.ErrorContains(t, err, "unable to decode PEM CA private key")
}

func TestGenerateLeaf_CAKeyNotPKCS8(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)
	ca.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a real key")}))

	_, err = GenerateLeaf(ca)
	assert.ErrorContains(t, err, "unable to parse CA private key")
}

func TestGenerateLeaf_CAKeyNotECDSA(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKeyDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	ca.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaKeyDER}))

	_, err = GenerateLeaf(ca)
	assert.ErrorContains(t, err, "CA private key is not an ECDSA key")
}

func TestExpiry(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	leaf, err := GenerateLeaf(ca)
	require.NoError(t, err)

	notAfter, err := Expiry(leaf.CertPEM)
	require.NoError(t, err)

	assert.WithinDuration(t, time.Now().Add(LeafValidity), notAfter, time.Minute)
}

func TestExpiry_InvalidPEM(t *testing.T) {
	t.Parallel()

	_, err := Expiry("not a pem block")
	assert.ErrorContains(t, err, "unable to decode PEM certificate")
}

func TestExpiry_InvalidCertificateBytes(t *testing.T) {
	t.Parallel()

	badCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a real cert")}))
	_, err := Expiry(badCertPEM)
	assert.ErrorContains(t, err, "unable to parse certificate")
}

func parsePEMCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// signLeafTemplate signs an arbitrary leaf template with the given CA's key,
// bypassing GenerateLeaf's fixed default SANs so tests can exercise SANs
// that fall outside the CA's name constraints.
func signLeafTemplate(t *testing.T, ca KeyPair, template *x509.Certificate) *x509.Certificate {
	t.Helper()

	caCert, caKey, err := parseCAKeyPair(ca)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template.SerialNumber, err = newSerialNumber()
	require.NoError(t, err)
	template.NotBefore = time.Now().Add(-time.Minute)
	template.NotAfter = time.Now().Add(LeafValidity)
	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	template.BasicConstraintsValid = true

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

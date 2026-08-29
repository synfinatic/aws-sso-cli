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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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

func TestGenerateLeaf_SignedByCA(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	leaf, err := GenerateLeaf(ca, nil)
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

	leaf, err := GenerateLeaf(ca, nil)
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

func TestGenerateLeaf_ExtraSANs(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	leaf, err := GenerateLeaf(ca, []string{"myhost.local", "10.0.0.5", "localhost"})
	require.NoError(t, err)

	cert := parsePEMCert(t, leaf.CertPEM)

	assert.Contains(t, cert.DNSNames, "myhost.local")
	// "localhost" was already a default SAN and should not be duplicated.
	assert.Equal(t, 1, countOccurrences(cert.DNSNames, "localhost"))

	ips := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ips[i] = ip.String()
	}
	assert.Contains(t, ips, "10.0.0.5")
}

func TestGenerateLeaf_UntrustedCARejected(t *testing.T) {
	t.Parallel()

	ca1, err := GenerateCA()
	require.NoError(t, err)
	ca2, err := GenerateCA()
	require.NoError(t, err)

	leaf, err := GenerateLeaf(ca1, nil)
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

func TestGenerateLeaf_InvalidCACert(t *testing.T) {
	t.Parallel()

	_, err := GenerateLeaf(KeyPair{CertPEM: "not a cert", KeyPEM: "not a key"}, nil)
	assert.Error(t, err)
}

func TestGenerateLeaf_InvalidCAKeyPEM(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	_, err = GenerateLeaf(KeyPair{CertPEM: ca.CertPEM, KeyPEM: "not a key"}, nil)
	assert.Error(t, err)
}

func TestGenerateLeaf_UnparsableCAKey(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	badKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})
	_, err = GenerateLeaf(KeyPair{CertPEM: ca.CertPEM, KeyPEM: string(badKeyPEM)}, nil)
	assert.Error(t, err)
}

func TestGenerateLeaf_NonECDSACAKey(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = GenerateLeaf(KeyPair{CertPEM: ca.CertPEM, KeyPEM: string(keyPEM)}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an ECDSA key")
}

func TestFingerprint_ValidPEMInvalidDER(t *testing.T) {
	t.Parallel()

	badCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	_, err := Fingerprint(string(badCertPEM))
	assert.Error(t, err)
}

func TestNotAfter(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA()
	require.NoError(t, err)

	notAfter, err := NotAfter(ca.CertPEM)
	require.NoError(t, err)

	cert := parsePEMCert(t, ca.CertPEM)
	assert.Equal(t, cert.NotAfter, notAfter)

	_, err = NotAfter("not a cert")
	assert.Error(t, err)
}

func parsePEMCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func countOccurrences(items []string, target string) int {
	count := 0
	for _, item := range items {
		if item == target {
			count++
		}
	}
	return count
}

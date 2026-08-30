package main

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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
)

// TestNewClient_TrustsLeafMintedFromStoredCA proves newClient() trusts
// whichever leaf is actually being served, via CA-based chain verification,
// rather than pinning one specific stored leaf value (there's no such value
// to pin anymore -- leaves are minted fresh and never persisted).
func TestNewClient_TrustsLeafMintedFromStoredCA(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	storeCaForTest(t, ctx)

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	caKey, err := ctx.Store.GetEcsCaKey()
	require.NoError(t, err)

	leaf, err := certutil.GenerateLeaf(certutil.KeyPair{CertPEM: caCert, KeyPEM: caKey})
	require.NoError(t, err)

	tlsCert, err := tls.X509KeyPair([]byte(leaf.CertPEM), []byte(leaf.KeyPEM))
	require.NoError(t, err)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	ts.StartTLS()
	defer ts.Close()

	c := newClient(ts.Listener.Addr().String(), ctx)
	_, err = c.ListProfiles()
	require.NoError(t, err, "client built from a CA-only store should trust a leaf minted from that CA")
}

// TestNewClient_RejectsUnrelatedCA confirms the CA-based trust actually
// verifies the chain rather than trusting anything: a leaf signed by an
// unrelated CA must be rejected.
func TestNewClient_RejectsUnrelatedCA(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	storeCaForTest(t, ctx)

	unrelatedCA, err := certutil.GenerateCA()
	require.NoError(t, err)
	leaf, err := certutil.GenerateLeaf(unrelatedCA)
	require.NoError(t, err)

	tlsCert, err := tls.X509KeyPair([]byte(leaf.CertPEM), []byte(leaf.KeyPEM))
	require.NoError(t, err)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	ts.StartTLS()
	defer ts.Close()

	c := newClient(ts.Listener.Addr().String(), ctx)
	_, err = c.ListProfiles()
	require.Error(t, err)
	var certErr x509.UnknownAuthorityError
	require.ErrorAs(t, err, &certErr, "leaf signed by an unrelated CA must fail chain verification")
}

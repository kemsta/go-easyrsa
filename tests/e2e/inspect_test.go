//go:build e2e

package e2e

import (
	"testing"

	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestShowCert — Pattern B: easy-rsa writes, go-easyrsa reads.
func TestShowCert(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	pair, err := p.ShowCert("client1")
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.Equal(t, "client1", pair.Name)
}

// TestShowCRL — Pattern B: easy-rsa writes, go-easyrsa reads.
func TestShowCRL(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("gen-crl")

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	crl, err := p.ShowCRL()
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.NotNil(t, crl)
}

// TestShowExpiring — Pattern B: easy-rsa writes, go-easyrsa reads expiring certs.
func TestShowExpiring(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	pairs, err := p.ShowExpiring(9999) // large window to include the cert
	require.NoError(t, err)            // fails: ErrNotImplemented
	assert.NotNil(t, pairs)
}

// TestShowRevoked — Pattern B: easy-rsa writes+revokes, go-easyrsa reads.
func TestShowRevoked(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")
	er.Run("revoke", "client1")

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	pairs, err := p.ShowRevoked()
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.Len(t, pairs, 1)
}

// TestVerifyCert_Revoked — Pattern B: easy-rsa writes+revokes+gen-crl, go-easyrsa verifies.
func TestVerifyCert_Revoked(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")
	er.Run("revoke", "client1")
	er.Run("gen-crl")

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	err = p.VerifyCert("client1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

// TestVerifyCert — Pattern B: easy-rsa writes, go-easyrsa verifies.
func TestVerifyCert(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	err = p.VerifyCert("client1")
	require.NoError(t, err) // fails: ErrNotImplemented
}

// TestUpdateDB — Pattern B: easy-rsa writes, go-easyrsa updates index.
func TestUpdateDB(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	err = p.UpdateDB()
	require.NoError(t, err) // fails: ErrNotImplemented
}

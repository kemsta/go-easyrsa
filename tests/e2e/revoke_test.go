//go:build e2e

package e2e

import (
	"testing"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRevoke — Pattern A: go-easyrsa revokes, easy-rsa verifies via show-crl.
func TestRevoke(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)

	err = p.Revoke("client1", cert.ReasonUnspecified)
	require.NoError(t, err) // fails: ErrNotImplemented

	out := er.Run("show-crl")
	assert.Contains(t, out, "Revoked Certificates")
}

// TestRevokeBySerial — Pattern A: go-easyrsa revokes by serial, easy-rsa verifies.
func TestRevokeBySerial(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)

	pair, err := p.ShowCert("client1")
	require.NoError(t, err) // fails: ErrNotImplemented

	serial, err := pair.Serial()
	require.NoError(t, err)

	err = p.RevokeBySerial(serial, cert.ReasonKeyCompromise)
	require.NoError(t, err) // fails: ErrNotImplemented
}

// TestRevokeExpired — Pattern B: easy-rsa writes, go-easyrsa revokes expired.
func TestRevokeExpired(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)

	err = p.RevokeExpired("client1", cert.ReasonCessationOfOperation)
	require.NoError(t, err) // fails: ErrNotImplemented
}

// TestGenCRL — Pattern A: go-easyrsa generates CRL, easy-rsa can show it.
func TestGenCRL(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)

	crlPEM, err := p.GenCRL()
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.NotEmpty(t, crlPEM)
}

// TestIsRevoked — Pattern B: easy-rsa revokes, go-easyrsa checks.
func TestIsRevoked(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")
	er.Run("revoke", "client1")
	er.Run("gen-crl")

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	// Get the serial of the revoked cert via PKI.
	pair, err := p.ShowCert("client1")
	require.NoError(t, err) // fails: ErrNotImplemented

	serial, err := pair.Serial()
	require.NoError(t, err)

	revoked, err := p.IsRevoked(serial)
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.True(t, revoked)
}

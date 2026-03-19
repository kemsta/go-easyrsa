//go:build e2e

package e2e

import (
	"testing"

	"github.com/kemsta/go-easyrsa/internal/testutil"
	"github.com/kemsta/go-easyrsa/pki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildClientFull — Pattern A: go-easyrsa writes, easy-rsa verifies.
func TestBuildClientFull(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)

	_, err = p.BuildClientFull("client1", pki.WithNoPass())
	require.NoError(t, err) // fails: ErrNotImplemented

	out := er.Run("show-cert", "client1")
	assert.Contains(t, out, "client1")
}

// TestBuildServerFull — Pattern A: go-easyrsa writes, easy-rsa verifies.
func TestBuildServerFull(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)

	_, err = p.BuildServerFull("server1", pki.WithNoPass())
	require.NoError(t, err) // fails: ErrNotImplemented

	out := er.Run("show-cert", "server1")
	assert.Contains(t, out, "server1")
}

// TestBuildServerClientFull — Pattern A: go-easyrsa writes, easy-rsa verifies.
func TestBuildServerClientFull(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)

	_, err = p.BuildServerClientFull("sc1", pki.WithNoPass())
	require.NoError(t, err) // fails: ErrNotImplemented

	out := er.Run("show-cert", "sc1")
	assert.Contains(t, out, "sc1")
}

// TestRenew — Pattern B: easy-rsa writes, go-easyrsa renews.
func TestRenew(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)

	pair, err := p.Renew("client1", pki.WithNoPass())
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.Equal(t, "client1", pair.Name)
}

// TestExpireCert — Pattern B: easy-rsa writes, go-easyrsa expires.
func TestExpireCert(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	err = p.ExpireCert("client1")
	require.NoError(t, err) // fails: ErrNotImplemented
}

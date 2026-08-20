//go:build e2e

package e2e

import (
	"path/filepath"
	"testing"

	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/pki"
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
	require.NoError(t, err)
	assert.Equal(t, "client1", pair.Name)
	require.FileExists(t, filepath.Join(pkiDir, "renewed", "issued", "client1.crt"))
	er.Run("show-cert", "client1")
	renewedStatus := er.Run("show-renew", "client1")
	assert.Contains(t, renewedStatus, "client1")
}

// TestExpire — Pattern B: easy-rsa writes, go-easyrsa moves the issued certificate.
func TestExpire(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)
	require.NoError(t, p.Expire("client1"))
	require.FileExists(t, filepath.Join(pkiDir, "expired", "client1.crt"))
}

// TestExpireCert — Pattern B: easy-rsa writes, go-easyrsa changes only the index.
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

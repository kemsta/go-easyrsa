//go:build e2e

package e2e

import (
	"testing"

	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupPKIWithClient(t *testing.T) (pkiDir string, er *testutil.Runner) {
	t.Helper()
	pkiDir = t.TempDir()
	er = testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")
	return pkiDir, er
}

// TestExportP12 — Pattern B: easy-rsa writes, go-easyrsa exports PKCS#12.
func TestExportP12(t *testing.T) {
	pkiDir, _ := setupPKIWithClient(t)

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	data, err := p.ExportP12("client1", "testpassword")
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.NotEmpty(t, data)
}

// TestExportP7 — Pattern B: easy-rsa writes, go-easyrsa exports PKCS#7.
func TestExportP7(t *testing.T) {
	pkiDir, _ := setupPKIWithClient(t)

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	data, err := p.ExportP7("client1")
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.NotEmpty(t, data)
}

// TestExportP8 — Pattern B: easy-rsa writes, go-easyrsa exports PKCS#8.
func TestExportP8(t *testing.T) {
	pkiDir, _ := setupPKIWithClient(t)

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	data, err := p.ExportP8("client1", "testpassword")
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.NotEmpty(t, data)
}

// TestExportP1 — Pattern B: easy-rsa writes, go-easyrsa exports PKCS#1.
func TestExportP1(t *testing.T) {
	pkiDir, _ := setupPKIWithClient(t)

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	data, err := p.ExportP1("client1")
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.NotEmpty(t, data)
}

// TestGenDH — Pattern A: go-easyrsa generates DH params (no easy-rsa setup needed).
func TestGenDH(t *testing.T) {
	pkiDir := t.TempDir()
	_ = testutil.NewRunner(t, pkiDir) // ensures binary exists

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	data, err := p.GenDH(512) // small size for test speed
	require.NoError(t, err)   // fails: ErrNotImplemented
	assert.NotEmpty(t, data)
}

// TestSetPass — Pattern B: easy-rsa writes, go-easyrsa changes passphrase.
func TestSetPass(t *testing.T) {
	pkiDir, _ := setupPKIWithClient(t)

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	err = p.SetPass("client1", "", "newpassword")
	require.NoError(t, err) // fails: ErrNotImplemented
}

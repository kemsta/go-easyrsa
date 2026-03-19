//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kemsta/go-easyrsa/cert"
	"github.com/kemsta/go-easyrsa/internal/testutil"
	"github.com/kemsta/go-easyrsa/pki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenReq — Pattern A: go-easyrsa generates a CSR, easy-rsa signs it.
func TestGenReq(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)

	csrPEM, err := p.GenReq("req1", pki.WithNoPass(), pki.WithCN("req1"))
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.NotEmpty(t, csrPEM)

	out := er.Run("sign-req", "client", "req1")
	assert.Contains(t, out, "req1")
}

// TestImportReq — Pattern B: easy-rsa generates a CSR, go-easyrsa imports it.
func TestImportReq(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("gen-req", "req1", "nopass")

	// Read the CSR file that easy-rsa generated directly (show-req outputs human-readable text, not PEM).
	csrPEM, err := os.ReadFile(filepath.Join(pkiDir, "reqs", "req1.req"))
	require.NoError(t, err)

	p, err2 := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err2)

	err = p.ImportReq("req1", csrPEM)
	require.NoError(t, err) // fails: ErrNotImplemented
}

// TestSignReq — Pattern B: easy-rsa writes, go-easyrsa signs.
func TestSignReq(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("gen-req", "req1", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)

	pair, err := p.SignReq("req1", cert.CertTypeClient)
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.Equal(t, "req1", pair.Name)
}

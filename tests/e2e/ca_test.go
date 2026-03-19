//go:build e2e

package e2e

import (
	"testing"

	"github.com/kemsta/go-easyrsa/internal/testutil"
	"github.com/kemsta/go-easyrsa/pki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildCA — Pattern A: go-easyrsa writes, easy-rsa verifies.
func TestBuildCA(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)

	p, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)

	_, err = p.BuildCA(pki.WithNoPass())
	require.NoError(t, err) // fails: ErrNotImplemented

	out := er.Run("show-ca")
	assert.Contains(t, out, "CA")
}

// TestRenewCA — Pattern A: go-easyrsa renews, easy-rsa verifies.
func TestRenewCA(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("--nopass", "build-ca", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)

	_, err = p.RenewCA(pki.WithNoPass())
	require.NoError(t, err) // fails: ErrNotImplemented

	out := er.Run("show-ca")
	assert.Contains(t, out, "CA")
}

// TestShowCA — Pattern B: easy-rsa writes, go-easyrsa reads.
func TestShowCA(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")

	p, err := pki.NewWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	pair, err := p.ShowCA()
	require.NoError(t, err) // fails: ErrNotImplemented
	assert.Equal(t, "ca", pair.Name)
}

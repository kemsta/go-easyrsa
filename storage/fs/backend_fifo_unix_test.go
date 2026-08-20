//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package fs_test

import (
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/storage"
	fsstore "github.com/kemsta/go-easyrsa/v2/storage/fs"
)

func TestBackendUpdateRejectsFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	backend := fsstore.NewBackend(pkiDir, "ca")
	require.NoError(t, backend.EnsureLayout())
	fifo := filepath.Join(pkiDir, "issued", "client.crt")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))

	called := false
	err := backend.Update(func(storage.Components) error {
		called = true
		return nil
	})
	require.Error(t, err)
	require.False(t, called)
}

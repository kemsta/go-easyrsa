//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package fs_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/storage"
	fsstore "github.com/kemsta/go-easyrsa/v2/storage/fs"
)

func TestLifecycleListRenewedRejectsFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	directory := filepath.Join(pkiDir, "renewed", "issued")
	require.NoError(t, os.MkdirAll(directory, 0o755))
	require.NoError(t, syscall.Mkfifo(filepath.Join(directory, "client.crt"), 0o600))

	_, err := fsstore.NewLifecycleStorage(pkiDir).ListRenewed()
	require.Error(t, err)

	directoryFIFOPath := filepath.Join(t.TempDir(), "pki")
	require.NoError(t, os.MkdirAll(filepath.Join(directoryFIFOPath, "renewed"), 0o755))
	require.NoError(t, syscall.Mkfifo(filepath.Join(directoryFIFOPath, "renewed", "issued"), 0o600))
	_, err = fsstore.NewLifecycleStorage(directoryFIFOPath).ListRenewed()
	require.Error(t, err)
}

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

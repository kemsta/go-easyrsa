//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package pki_test

import (
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/pki"
)

func TestUtilityInputFIFOIsNeverOpened(t *testing.T) {
	t.Parallel()

	fifo := filepath.Join(t.TempDir(), "input")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	pk, err := pki.NewWithMemory(pki.Config{})
	require.NoError(t, err)
	_, err = pk.DisplayDN(pki.DNFormX509, fifo)
	require.Error(t, err)
	_, err = pk.ShowEKU(fifo)
	require.Error(t, err)
}

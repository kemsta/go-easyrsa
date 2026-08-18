//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReadRegularPKIFile_RejectsFIFOWithoutOpeningIt(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.txt"), nil, 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "issued"), 0o755))
	fifo := filepath.Join(dir, "issued", "alice.crt")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))

	session, err := openLifecycleSession(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	started := time.Now()
	_, err = session.readRegular(filepath.Join("issued", "alice.crt"))
	require.Error(t, err)
	require.Less(t, time.Since(started), time.Second)
}

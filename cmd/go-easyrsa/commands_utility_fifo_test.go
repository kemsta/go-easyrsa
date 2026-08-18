//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/pki"
)

func TestOpenRegularPathRejectsFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "input")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	started := time.Now()
	file, regular, err := openRegularPath(fifo)
	require.NoError(t, err)
	assert.Nil(t, file)
	assert.False(t, regular)
	assert.Less(t, time.Since(started), time.Second)
}

func TestOpenRegularPathDetectsReplacementWithFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	require.NoError(t, os.WriteFile(path, []byte("certificate"), 0o600))

	started := time.Now()
	file, regular, err := openRegularPathWith(path, func(name string) (*os.File, error) {
		require.NoError(t, os.Remove(name))
		require.NoError(t, syscall.Mkfifo(name, 0o600))
		return openReadOnlyPath(name)
	})
	require.NoError(t, err)
	assert.Nil(t, file)
	assert.False(t, regular)
	assert.Less(t, time.Since(started), time.Second)
}

func TestCLI_ShowEKUFIFOFallsBackToName(t *testing.T) {
	workingDir := t.TempDir()
	t.Chdir(workingDir)
	require.NoError(t, syscall.Mkfifo("alice", 0o600))

	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk := openFS(t, pkiDir, pki.Config{NoPass: true})
	_, err := pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("alice")
	require.NoError(t, err)

	started := time.Now()
	out, err := runCLI(t, "--pki-dir", pkiDir, "show-eku", "alice")
	require.NoError(t, err, out)
	assert.Equal(t, "client\n", out)
	assert.Less(t, time.Since(started), time.Second)
}

func TestCLI_DisplayDNRejectsFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "subject")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	started := time.Now()
	_, err := runCLI(t, "display-dn", "x509", fifo)
	require.Error(t, err)
	assert.Less(t, time.Since(started), time.Second)
}

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWritePKIArtifact_ReplacesAtomicallyWithRequestedMode(t *testing.T) {
	dir := t.TempDir()
	relative := filepath.Join("private", "alice.p8")

	path, err := writePKIArtifact(dir, relative, []byte("first"), 0o600)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, relative), path)

	path, err = writePKIArtifact(dir, relative, []byte("second"), 0o600)
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("second"), data)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".alice.p8.tmp-*"))
	require.NoError(t, err)
	require.Empty(t, matches)
}

func TestWritePKIArtifact_RejectsEscapingSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "private")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, err := writePKIArtifact(dir, filepath.Join("private", "alice.p8"), []byte("secret"), 0o600)
	require.Error(t, err)
	_, statErr := os.Stat(filepath.Join(outside, "alice.p8"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestWritePKIArtifact_RejectsEscapingPath(t *testing.T) {
	dir := t.TempDir()

	_, err := writePKIArtifact(dir, filepath.Join("..", "outside"), []byte("secret"), 0o600)
	require.Error(t, err)
	absolute, err := filepath.Abs(filepath.Join(dir, "outside"))
	require.NoError(t, err)
	_, err = writePKIArtifact(dir, absolute, []byte("secret"), 0o600)
	require.Error(t, err)
}

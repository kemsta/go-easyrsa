//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package fs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenewalEntryReadStaysBoundToOpenedDirectory(t *testing.T) {
	t.Parallel()
	pkiDir := t.TempDir()
	directoryName := filepath.Join("renewed", "issued")
	originalPath := filepath.Join(pkiDir, directoryName)
	require.NoError(t, os.MkdirAll(originalPath, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(originalPath, "client.crt"), []byte("original"), 0o644))
	root, err := os.OpenRoot(pkiDir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	directory, err := openRenewalDirectory(root, directoryName)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, directory.Close()) })
	entries, err := directory.file.ReadDir(-1)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	expected, err := entries[0].Info()
	require.NoError(t, err)

	require.NoError(t, os.Rename(originalPath, filepath.Join(pkiDir, "renewed", "old")))
	require.NoError(t, os.Mkdir(originalPath, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(originalPath, "client.crt"), []byte("replacement"), 0o644))

	data, err := readRenewalEntry(directory.file, root, filepath.Join(directoryName, "client.crt"), "client.crt", expected)
	require.NoError(t, err)
	require.Equal(t, []byte("original"), data)
}

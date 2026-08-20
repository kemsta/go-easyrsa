package fs

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenewalDirectoryIdentityRejectsReplacement(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("open directory handles prevent replacement on Windows")
	}
	pkiDir := t.TempDir()
	directoryName := filepath.Join("renewed", "issued")
	require.NoError(t, os.MkdirAll(filepath.Join(pkiDir, directoryName), 0o755))
	root, err := os.OpenRoot(pkiDir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })

	directory, err := openRenewalDirectory(root, directoryName)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, directory.Close()) })
	require.NoError(t, os.Rename(filepath.Join(pkiDir, directoryName), filepath.Join(pkiDir, "renewed", "old")))
	require.NoError(t, os.Mkdir(filepath.Join(pkiDir, directoryName), 0o755))

	require.Error(t, validateRenewalDirectoryIdentity(root, directoryName, directory.identities))
}

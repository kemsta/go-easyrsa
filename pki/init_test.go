package pki_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func TestInitPKIInitializesWithoutConstructorSideEffects(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.OpenWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)
	_, err = os.Stat(pkiDir)
	require.ErrorIs(t, err, os.ErrNotExist)

	require.NoError(t, pk.InitPKI(pki.InitPKIOptions{}))
	for _, directory := range []string{"private", "issued", "reqs", "certs_by_serial"} {
		require.DirExists(t, filepath.Join(pkiDir, directory))
	}
}

func TestInitPKIRequiresExplicitResetAndRestoresFreshLayout(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true, SequentialSerial: true})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("client")
	require.NoError(t, err)
	caBefore, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	require.NoError(t, err)

	require.ErrorIs(t, pk.InitPKI(pki.InitPKIOptions{}), storage.ErrConflict)
	caAfterConflict, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	require.NoError(t, err)
	require.Equal(t, caBefore, caAfterConflict)

	require.NoError(t, pk.InitPKI(pki.InitPKIOptions{Reset: true}))
	require.NoFileExists(t, filepath.Join(pkiDir, "ca.crt"))
	require.NoFileExists(t, filepath.Join(pkiDir, "issued", "client.crt"))
	require.DirExists(t, filepath.Join(pkiDir, "private"))
}

func TestInitPKIRejectsForeignStorageWithAndWithoutReset(t *testing.T) {
	t.Parallel()

	pkiDir := t.TempDir()
	foreign := filepath.Join(pkiDir, "foreign.txt")
	require.NoError(t, os.WriteFile(foreign, []byte("keep"), 0o600))
	pk, err := pki.OpenWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)
	for _, reset := range []bool{false, true} {
		err := pk.InitPKI(pki.InitPKIOptions{Reset: reset})
		require.ErrorIs(t, err, storage.ErrForeignStorage)
		require.Equal(t, []byte("keep"), mustReadInitFile(t, foreign))
	}
}

func TestInitPKIFailurePreservesExistingOwnedNamespace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional Windows privileges")
	}
	t.Parallel()

	pkiDir := t.TempDir()
	indexPath := filepath.Join(pkiDir, "index.txt")
	require.NoError(t, os.WriteFile(indexPath, []byte("owned marker"), 0o600))
	outside := filepath.Join(t.TempDir(), "outside")
	require.NoError(t, os.WriteFile(outside, []byte("outside"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(pkiDir, "unsafe-link")))
	pk, err := pki.OpenWithFS(pkiDir, pki.Config{})
	require.NoError(t, err)

	err = pk.InitPKI(pki.InitPKIOptions{Reset: true})
	require.Error(t, err)
	require.Equal(t, []byte("owned marker"), mustReadInitFile(t, indexPath))
	require.Equal(t, []byte("outside"), mustReadInitFile(t, outside))
	_, statErr := os.Lstat(filepath.Join(pkiDir, "unsafe-link"))
	require.NoError(t, statErr)
}

func TestNewWithFSNeverResetsExistingPKI(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	caBefore, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	require.NoError(t, err)

	_, err = pki.NewWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)
	caAfter, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	require.NoError(t, err)
	require.Equal(t, caBefore, caAfter)
}

func mustReadInitFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	require.NoError(t, err)
	return data
}

func TestInitPKIMemoryAndLegacySemantics(t *testing.T) {
	t.Parallel()

	memoryPKI, err := pki.NewWithMemory(pki.Config{NoPass: true})
	require.NoError(t, err)
	_, err = memoryPKI.BuildCA()
	require.NoError(t, err)
	require.ErrorIs(t, memoryPKI.InitPKI(pki.InitPKIOptions{}), storage.ErrConflict)
	require.NoError(t, memoryPKI.InitPKI(pki.InitPKIOptions{Reset: true}))
	_, err = memoryPKI.ShowCA()
	require.ErrorIs(t, err, storage.ErrNotFound)

	legacyDir := t.TempDir()
	testutil.WriteLegacyFixture(t, legacyDir)
	legacyPKI, err := pki.NewWithLegacyFSRO(legacyDir, pki.Config{})
	require.NoError(t, err)
	require.ErrorIs(t, legacyPKI.InitPKI(pki.InitPKIOptions{Reset: true}), storage.ErrReadOnly)
}

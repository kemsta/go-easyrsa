package fs_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	fs "github.com/kemsta/go-easyrsa/v2/storage/fs"
)

func TestOwnershipProbe_Empty(t *testing.T) {
	probe := fs.OwnershipProbe{Dir: t.TempDir()}
	empty, err := probe.Empty()
	require.NoError(t, err)
	require.True(t, empty)
}

func TestOwnershipProbe_Owned(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "issued"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.txt"), nil, 0o644))

	probe := fs.OwnershipProbe{Dir: dir}
	empty, err := probe.Empty()
	require.NoError(t, err)
	require.False(t, empty)
	owned, err := probe.Owned()
	require.NoError(t, err)
	require.True(t, owned)
}

func TestInitializeResetRejectsIndividualGenericMarkers(t *testing.T) {
	for _, marker := range []string{"private", "issued", "reqs", "certs_by_serial", "expired", "renewed", "revoked"} {
		marker := marker
		t.Run(marker, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(dir, marker), 0o755))
			unrelated := filepath.Join(dir, "unrelated.txt")
			require.NoError(t, os.WriteFile(unrelated, []byte("keep"), 0o600))
			backend := fs.NewBackend(dir, "ca")
			require.ErrorIs(t, backend.Initialize(true), storage.ErrForeignStorage)
			data, err := os.ReadFile(unrelated)
			require.NoError(t, err)
			require.Equal(t, []byte("keep"), data)
		})
	}
}

func TestOwnershipProbe_NotOwned(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteLegacyFixture(t, dir)

	probe := fs.OwnershipProbe{Dir: dir}
	empty, err := probe.Empty()
	require.NoError(t, err)
	require.False(t, empty)
	owned, err := probe.Owned()
	require.NoError(t, err)
	require.False(t, owned)
}

func TestNewWithFS_RejectsNonOwnedNonEmptyDir(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteLegacyFixture(t, dir)

	_, err := pki.NewWithFS(dir, pki.Config{})
	require.Error(t, err)
	require.ErrorContains(t, err, "does not look like the current PKI filesystem layout")
}

func TestNewWithFS_RejectsUnknownNonEmptyDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "random.txt"), []byte("x"), 0o644))

	_, err := pki.NewWithFS(dir, pki.Config{})
	require.Error(t, err)
	require.ErrorContains(t, err, "does not look like the current PKI filesystem layout")
}

func TestNewWithFS_AcceptsExistingCurrentLayout(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "private"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "issued"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.txt"), nil, 0o644))

	_, err := pki.NewWithFS(dir, pki.Config{})
	require.NoError(t, err)
}

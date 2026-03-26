package fs_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/internal/testutil"
	"github.com/kemsta/go-easyrsa/pki"
	fs "github.com/kemsta/go-easyrsa/storage/fs"
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

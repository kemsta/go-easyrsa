package legacy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage/legacy"
)

func TestOwnershipProbe_Owned(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteLegacyFixture(t, dir)

	probe := legacy.OwnershipProbe{Dir: dir}
	empty, err := probe.Empty()
	require.NoError(t, err)
	require.False(t, empty)
	owned, err := probe.Owned()
	require.NoError(t, err)
	require.True(t, owned)
}

func TestOwnershipProbe_NotOwned(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "issued"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.txt"), nil, 0o644))

	probe := legacy.OwnershipProbe{Dir: dir}
	empty, err := probe.Empty()
	require.NoError(t, err)
	require.False(t, empty)
	owned, err := probe.Owned()
	require.NoError(t, err)
	require.False(t, owned)
}

func TestNewWithLegacyFSRO_RejectsForeignDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "issued"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.txt"), nil, 0o644))

	_, err := pki.NewWithLegacyFSRO(dir, pki.Config{})
	require.Error(t, err)
}

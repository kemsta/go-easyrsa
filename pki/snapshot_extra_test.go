package pki_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/pki"
	fsstore "github.com/kemsta/go-easyrsa/v2/storage/fs"
)

func TestExportSnapshot_WithoutCRL(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteLegacyFixture(t, dir)
	require.NoError(t, os.Remove(filepath.Join(dir, "crl.pem")))

	source, err := pki.NewWithLegacyFSRO(dir, pki.Config{})
	require.NoError(t, err)
	snapshot, err := source.ExportSnapshot()
	require.NoError(t, err)
	require.Empty(t, snapshot.CRLPEM)
}

func TestImportSnapshot_FSTargetWithoutCRLDoesNotCreateOne(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteLegacyFixture(t, dir)
	require.NoError(t, os.Remove(filepath.Join(dir, "crl.pem")))

	source, err := pki.NewWithLegacyFSRO(dir, pki.Config{})
	require.NoError(t, err)
	snapshot, err := source.ExportSnapshot()
	require.NoError(t, err)
	targetDir := t.TempDir()
	target, err := pki.NewWithFS(targetDir, pki.Config{})
	require.NoError(t, err)
	require.NoError(t, target.ImportSnapshot(snapshot, source.ExportPairs))

	crl, err := fsstore.NewCRLHolder(targetDir).Get()
	require.NoError(t, err)
	require.Empty(t, crl.Raw)
}

package migration_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/internal/testutil"
	"github.com/kemsta/go-easyrsa/migration"
	"github.com/kemsta/go-easyrsa/pki"
	"github.com/kemsta/go-easyrsa/storage"
	"github.com/kemsta/go-easyrsa/storage/memory"
)

func TestMigrate_LegacyToFS(t *testing.T) {
	sourceDir := t.TempDir()
	testutil.WriteLegacyFixture(t, sourceDir)

	source, err := pki.NewWithLegacyFSRO(sourceDir, pki.Config{})
	require.NoError(t, err)

	targetDir := t.TempDir()
	target, err := pki.NewWithFS(targetDir, pki.Config{})
	require.NoError(t, err)

	require.NoError(t, migration.Migrate(source, target))

	sourceSnap, err := source.ExportSnapshot()
	require.NoError(t, err)
	targetSnap, err := target.ExportSnapshot()
	require.NoError(t, err)

	assertSnapshotEquivalent(t, sourceSnap, targetSnap)
	assertPairStreamsEquivalent(t, source, target)
}

func TestMigrate_FSToMemoryAndBack(t *testing.T) {
	legacyDir := t.TempDir()
	testutil.WriteLegacyFixture(t, legacyDir)

	legacyPKI, err := pki.NewWithLegacyFSRO(legacyDir, pki.Config{})
	require.NoError(t, err)

	fsDir := t.TempDir()
	fsPKI, err := pki.NewWithFS(fsDir, pki.Config{})
	require.NoError(t, err)
	require.NoError(t, migration.Migrate(legacyPKI, fsPKI))

	ks, cs, idx, sp, crl := memory.New()
	memoryPKI := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	require.NoError(t, migration.Migrate(fsPKI, memoryPKI))

	fsSnap, err := fsPKI.ExportSnapshot()
	require.NoError(t, err)
	memorySnap, err := memoryPKI.ExportSnapshot()
	require.NoError(t, err)
	assertSnapshotEquivalent(t, fsSnap, memorySnap)
	assertPairStreamsEquivalent(t, fsPKI, memoryPKI)

	fsDir2 := t.TempDir()
	fsPKI2, err := pki.NewWithFS(fsDir2, pki.Config{})
	require.NoError(t, err)
	require.NoError(t, migration.Migrate(memoryPKI, fsPKI2))

	fsSnap2, err := fsPKI2.ExportSnapshot()
	require.NoError(t, err)
	assertSnapshotEquivalent(t, memorySnap, fsSnap2)
	assertPairStreamsEquivalent(t, memoryPKI, fsPKI2)
}

func TestMigrate_LegacyWithoutCRL(t *testing.T) {
	sourceDir := t.TempDir()
	testutil.WriteLegacyFixture(t, sourceDir)
	require.NoError(t, os.Remove(filepath.Join(sourceDir, "crl.pem")))

	source, err := pki.NewWithLegacyFSRO(sourceDir, pki.Config{})
	require.NoError(t, err)
	targetDir := t.TempDir()
	target, err := pki.NewWithFS(targetDir, pki.Config{})
	require.NoError(t, err)

	require.NoError(t, migration.Migrate(source, target))

	crl, err := target.ShowCRL()
	require.NoError(t, err)
	require.Len(t, crl.RevokedCertificateEntries, 0)
}

func TestMigrate_LegacyPreservesHistoryInFSTarget(t *testing.T) {
	sourceDir := t.TempDir()
	fixture := testutil.WriteLegacyFixture(t, sourceDir)

	source, err := pki.NewWithLegacyFSRO(sourceDir, pki.Config{})
	require.NoError(t, err)
	targetDir := t.TempDir()
	target, err := pki.NewWithFS(targetDir, pki.Config{})
	require.NoError(t, err)

	require.NoError(t, migration.Migrate(source, target))
	assertPairStreamsEquivalent(t, source, target)

	latest, err := target.ShowCert("client1")
	require.NoError(t, err)
	latestSerial, err := latest.Serial()
	require.NoError(t, err)
	require.Zero(t, latestSerial.Cmp(testutil.MustSerial(t, fixture.ClientCurrent)))
}

func TestMigrate_LegacySetsNextSerial(t *testing.T) {
	sourceDir := t.TempDir()
	testutil.WriteLegacyFixture(t, sourceDir)

	source, err := pki.NewWithLegacyFSRO(sourceDir, pki.Config{})
	require.NoError(t, err)
	targetDir := t.TempDir()
	target, err := pki.NewWithFS(targetDir, pki.Config{SequentialSerial: true, NoPass: true})
	require.NoError(t, err)

	require.NoError(t, migration.Migrate(source, target))
	_, err = target.BuildClientFull("after-migrate")
	require.NoError(t, err)
	pair, err := target.ShowCert("after-migrate")
	require.NoError(t, err)
	serial, err := pair.Serial()
	require.NoError(t, err)
	require.Equal(t, "06", storage.HexSerial(serial))
}

func TestMigrate_LegacyWithMissingHistoricalKey(t *testing.T) {
	sourceDir := t.TempDir()
	fixture := testutil.WriteLegacyFixture(t, sourceDir)
	oldSerial := testutil.MustSerial(t, fixture.ClientOld)
	require.NoError(t, os.Remove(filepath.Join(sourceDir, "client1", oldSerial.Text(16)+".key")))

	source, err := pki.NewWithLegacyFSRO(sourceDir, pki.Config{})
	require.NoError(t, err)
	targetDir := t.TempDir()
	target, err := pki.NewWithFS(targetDir, pki.Config{})
	require.NoError(t, err)

	require.NoError(t, migration.Migrate(source, target))
	assertPairStreamsEquivalent(t, source, target)
}

func TestImportSnapshot_IntoNonEmptyTargetIsCurrentBehavior(t *testing.T) {
	sourceDir := t.TempDir()
	testutil.WriteLegacyFixture(t, sourceDir)
	source, err := pki.NewWithLegacyFSRO(sourceDir, pki.Config{})
	require.NoError(t, err)
	snapshot, err := source.ExportSnapshot()
	require.NoError(t, err)

	targetDir := t.TempDir()
	target, err := pki.NewWithFS(targetDir, pki.Config{NoPass: true})
	require.NoError(t, err)
	_, err = target.BuildCA()
	require.NoError(t, err)

	err = target.ImportSnapshot(snapshot, source.ExportPairs)
	require.NoError(t, err)
}

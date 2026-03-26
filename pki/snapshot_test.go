package pki_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/internal/testutil"
	"github.com/kemsta/go-easyrsa/pki"
	"github.com/kemsta/go-easyrsa/storage"
	"github.com/kemsta/go-easyrsa/storage/memory"
)

func TestExportSnapshot_LegacyContainsHistoryAndMetadata(t *testing.T) {
	dir := t.TempDir()
	fixture := testutil.WriteLegacyFixture(t, dir)

	source, err := pki.NewWithLegacyFSRO(dir, pki.Config{})
	require.NoError(t, err)

	snapshot, err := source.ExportSnapshot()
	require.NoError(t, err)
	require.NotNil(t, snapshot)

	assert.Equal(t, "ca", snapshot.CAName)
	require.NotNil(t, snapshot.NextSerial)
	assert.Equal(t, "06", storage.HexSerial(snapshot.NextSerial))
	assert.NotEmpty(t, snapshot.CRLPEM)
	assert.Len(t, snapshot.Index, 5)

	pairs := collectPairs(t, source)
	serials := make(map[string]bool, len(pairs))
	for _, pair := range pairs {
		serial, err := pair.Serial()
		require.NoError(t, err)
		serials[storage.HexSerial(serial)] = true
	}
	assert.True(t, serials[storage.HexSerial(testutil.MustSerial(t, fixture.CAPair))])
	assert.True(t, serials[storage.HexSerial(testutil.MustSerial(t, fixture.ClientOld))])
	assert.True(t, serials[storage.HexSerial(testutil.MustSerial(t, fixture.ClientCurrent))])
	assert.True(t, serials[storage.HexSerial(testutil.MustSerial(t, fixture.ExpiredPair))])
	assert.True(t, serials[storage.HexSerial(testutil.MustSerial(t, fixture.RevokedPair))])
}

func TestImportSnapshot_MemoryPreservesHistoryAndStatuses(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteLegacyFixture(t, dir)

	source, err := pki.NewWithLegacyFSRO(dir, pki.Config{})
	require.NoError(t, err)
	snapshot, err := source.ExportSnapshot()
	require.NoError(t, err)

	ks, cs, idx, sp, crl := memory.New()
	target, err := pki.New(pki.Config{CAName: snapshot.CAName}, ks, cs, idx, sp, crl)
	require.NoError(t, err)
	require.NoError(t, target.ImportSnapshot(snapshot, source.ExportPairs))

	pairs, err := ks.GetByName("client1")
	require.NoError(t, err)
	assert.Len(t, pairs, 2)

	exported, err := target.ExportSnapshot()
	require.NoError(t, err)
	assertSnapshotEquivalent(t, snapshot, exported)
	assertPairStreamsEquivalent(t, source, target)
}

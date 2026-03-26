package legacy_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/internal/testutil"
	"github.com/kemsta/go-easyrsa/storage"
	"github.com/kemsta/go-easyrsa/storage/legacy"
)

func TestKeyStorage_GetByNameAndGetLastByName(t *testing.T) {
	dir := t.TempDir()
	fixture := testutil.WriteLegacyFixture(t, dir)
	ks := legacy.NewKeyStorage(dir, "ca")

	pairs, err := ks.GetByName("client1")
	require.NoError(t, err)
	require.Len(t, pairs, 2)

	oldSerial := testutil.MustSerial(t, fixture.ClientOld)
	currentSerial := testutil.MustSerial(t, fixture.ClientCurrent)
	got0, err := pairs[0].Serial()
	require.NoError(t, err)
	got1, err := pairs[1].Serial()
	require.NoError(t, err)
	assert.Zero(t, got0.Cmp(oldSerial))
	assert.Zero(t, got1.Cmp(currentSerial))

	last, err := ks.GetLastByName("client1")
	require.NoError(t, err)
	lastSerial, err := last.Serial()
	require.NoError(t, err)
	assert.Zero(t, lastSerial.Cmp(currentSerial))
}

func TestKeyStorage_GetBySerial(t *testing.T) {
	dir := t.TempDir()
	fixture := testutil.WriteLegacyFixture(t, dir)
	ks := legacy.NewKeyStorage(dir, "ca")

	pair, err := ks.GetBySerial(testutil.MustSerial(t, fixture.RevokedPair))
	require.NoError(t, err)
	assert.Equal(t, "revoked1", pair.Name)
	assert.Equal(t, fixture.RevokedPair.CertPEM, pair.CertPEM)
}

func TestKeyStorage_MissingCompanionKeyStillReturnsCert(t *testing.T) {
	dir := t.TempDir()
	fixture := testutil.WriteLegacyFixture(t, dir)
	serial := testutil.MustSerial(t, fixture.ExpiredPair)
	serialHex := serial.Text(16)
	require.NoError(t, os.Remove(filepath.Join(dir, "expired1", serialHex+".key")))

	ks := legacy.NewKeyStorage(dir, "ca")
	pair, err := ks.GetBySerial(serial)
	require.NoError(t, err)
	assert.Equal(t, "expired1", pair.Name)
	assert.Nil(t, pair.KeyPEM)
	assert.NotNil(t, pair.CertPEM)
}

func TestIndexDB_QueryDerivesStatusesFromCertsAndCRL(t *testing.T) {
	dir := t.TempDir()
	fixture := testutil.WriteLegacyFixture(t, dir)
	ks := legacy.NewKeyStorage(dir, "ca")
	crl := legacy.NewCRLHolder(dir)
	db := legacy.NewIndexDB(ks, crl)

	entries, err := db.Query(storage.IndexFilter{})
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	statuses := map[string]storage.CertStatus{}
	for _, e := range entries {
		statuses[storage.HexSerial(e.Serial)] = e.Status
	}

	assert.Equal(t, storage.StatusValid, statuses[storage.HexSerial(testutil.MustSerial(t, fixture.CAPair))])
	assert.Equal(t, storage.StatusValid, statuses[storage.HexSerial(testutil.MustSerial(t, fixture.ClientOld))])
	assert.Equal(t, storage.StatusValid, statuses[storage.HexSerial(testutil.MustSerial(t, fixture.ClientCurrent))])
	assert.Equal(t, storage.StatusExpired, statuses[storage.HexSerial(testutil.MustSerial(t, fixture.ExpiredPair))])
	assert.Equal(t, storage.StatusRevoked, statuses[storage.HexSerial(testutil.MustSerial(t, fixture.RevokedPair))])

	revokedStatus := storage.StatusRevoked
	revoked, err := db.Query(storage.IndexFilter{Status: &revokedStatus})
	require.NoError(t, err)
	require.Len(t, revoked, 1)
	assert.Zero(t, revoked[0].Serial.Cmp(testutil.MustSerial(t, fixture.RevokedPair)))
}

func TestReadOnlyComponentsRejectWrites(t *testing.T) {
	dir := t.TempDir()
	fixture := testutil.WriteLegacyFixture(t, dir)
	ks := legacy.NewKeyStorage(dir, "ca")
	crl := legacy.NewCRLHolder(dir)
	db := legacy.NewIndexDB(ks, crl)
	cs := legacy.NewCSRStorage()
	sp := legacy.NewSerialProvider()

	assert.ErrorIs(t, ks.Put(fixture.ClientCurrent), storage.ErrReadOnly)
	assert.ErrorIs(t, ks.DeleteByName("client1"), storage.ErrReadOnly)
	assert.ErrorIs(t, ks.DeleteBySerial(testutil.MustSerial(t, fixture.ClientCurrent)), storage.ErrReadOnly)
	assert.ErrorIs(t, db.Record(storage.IndexEntry{}), storage.ErrReadOnly)
	assert.ErrorIs(t, db.Update(testutil.MustSerial(t, fixture.ClientCurrent), storage.StatusRevoked, time.Now(), 0), storage.ErrReadOnly)
	assert.ErrorIs(t, db.RecordAndUpdate(storage.IndexEntry{}, testutil.MustSerial(t, fixture.ClientCurrent), storage.StatusExpired, time.Now(), 0), storage.ErrReadOnly)
	assert.ErrorIs(t, cs.PutCSR("x", []byte("csr")), storage.ErrReadOnly)
	_, err := cs.GetCSR("x")
	assert.ErrorIs(t, err, storage.ErrReadOnly)
	_, err = cs.ListCSRs()
	assert.ErrorIs(t, err, storage.ErrReadOnly)
	_, err = sp.Next()
	assert.ErrorIs(t, err, storage.ErrReadOnly)
	assert.ErrorIs(t, crl.Put([]byte("pem")), storage.ErrReadOnly)
	_, err = crl.Get()
	require.NoError(t, err)
}

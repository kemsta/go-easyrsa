package legacy_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/legacy"
)

func TestLegacyExportPairs_StreamsAllPairsInLegacyOrder(t *testing.T) {
	dir := t.TempDir()
	fixture := testutil.WriteLegacyFixture(t, dir)
	ks := legacy.NewKeyStorage(dir, "ca")

	var got []string
	err := ks.ExportPairs(func(pair *cert.Pair) error {
		serial, err := pair.Serial()
		require.NoError(t, err)
		got = append(got, pair.Name+":"+storage.HexSerial(serial))
		return nil
	})
	require.NoError(t, err)

	assert.Equal(t, []string{
		"ca:" + storage.HexSerial(testutil.MustSerial(t, fixture.CAPair)),
		"client1:" + storage.HexSerial(testutil.MustSerial(t, fixture.ClientOld)),
		"client1:" + storage.HexSerial(testutil.MustSerial(t, fixture.ClientCurrent)),
		"expired1:" + storage.HexSerial(testutil.MustSerial(t, fixture.ExpiredPair)),
		"revoked1:" + storage.HexSerial(testutil.MustSerial(t, fixture.RevokedPair)),
	}, got)
}

func TestLegacyExportPairs_StopsOnYieldError(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteLegacyFixture(t, dir)
	ks := legacy.NewKeyStorage(dir, "ca")

	wantErr := errors.New("stop")
	calls := 0
	err := ks.ExportPairs(func(*cert.Pair) error {
		calls++
		return wantErr
	})
	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, 1, calls)
}

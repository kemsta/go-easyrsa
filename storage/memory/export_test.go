package memory_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func TestMemoryExportPairs_SortsBySerialAndCopiesPayloads(t *testing.T) {
	backend, pk := newMemoryPKI(t)

	_, err := pk.BuildCA()
	require.NoError(t, err)
	pair2, err := pk.BuildClientFull("client2")
	require.NoError(t, err)
	pair1, err := pk.BuildClientFull("client1")
	require.NoError(t, err)

	var exported []*cert.Pair
	require.NoError(t, backend.View(func(components storage.Components) error {
		exported = collectExportedPairs(t, components.Keys().(storage.PairExporter))
		return nil
	}))
	require.Len(t, exported, 3)

	assert.Equal(t, []string{
		"ca:" + storage.HexSerial(mustSerial(t, exported[0])),
		"client2:" + storage.HexSerial(mustSerial(t, exported[1])),
		"client1:" + storage.HexSerial(mustSerial(t, exported[2])),
	}, []string{
		exported[0].Name + ":" + storage.HexSerial(mustSerial(t, exported[0])),
		exported[1].Name + ":" + storage.HexSerial(mustSerial(t, exported[1])),
		exported[2].Name + ":" + storage.HexSerial(mustSerial(t, exported[2])),
	})

	var original *cert.Pair
	require.NoError(t, backend.View(func(components storage.Components) error {
		var err error
		original, err = components.Keys().GetBySerial(mustSerial(t, pair1))
		return err
	}))
	exported[2].KeyPEM[0] ^= 0xFF
	exported[2].CertPEM[0] ^= 0xFF
	require.NoError(t, backend.View(func(components storage.Components) error {
		again, err := components.Keys().GetBySerial(mustSerial(t, pair1))
		require.NoError(t, err)
		assert.Equal(t, original.KeyPEM, again.KeyPEM)
		assert.Equal(t, original.CertPEM, again.CertPEM)
		return nil
	}))

	_ = pair2 // keeps intent explicit: exported order is based on serial, not lexical name order.
}

func TestMemoryExportPairs_StopsOnYieldError(t *testing.T) {
	backend, pk := newMemoryPKI(t)

	_, err := pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("client1")
	require.NoError(t, err)

	wantErr := errors.New("stop")
	calls := 0
	err = backend.View(func(components storage.Components) error {
		return components.Keys().(storage.PairExporter).ExportPairs(func(*cert.Pair) error {
			calls++
			return wantErr
		})
	})
	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, 1, calls)
}

package pki_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func collectPairs(t *testing.T, pk *pki.PKI) []*cert.Pair {
	t.Helper()
	var pairs []*cert.Pair
	err := pk.ExportPairs(func(pair *cert.Pair) error {
		cp := &cert.Pair{Name: pair.Name, CertPEM: append([]byte(nil), pair.CertPEM...), KeyPEM: append([]byte(nil), pair.KeyPEM...)}
		pairs = append(pairs, cp)
		return nil
	})
	require.NoError(t, err)
	return pairs
}

func assertSnapshotEquivalent(t *testing.T, want, got *pki.Snapshot) {
	t.Helper()
	require.NotNil(t, want)
	require.NotNil(t, got)

	assert.Equal(t, want.CAName, got.CAName)
	require.NotNil(t, want.NextSerial)
	require.NotNil(t, got.NextSerial)
	assert.Equal(t, storage.HexSerial(want.NextSerial), storage.HexSerial(got.NextSerial))
	assert.Equal(t, len(want.Index), len(got.Index))

	wantIndex := make([]string, 0, len(want.Index))
	gotIndex := make([]string, 0, len(got.Index))
	for _, entry := range want.Index {
		wantIndex = append(wantIndex, string(entry.Status)+":"+storage.HexSerial(entry.Serial))
	}
	for _, entry := range got.Index {
		gotIndex = append(gotIndex, string(entry.Status)+":"+storage.HexSerial(entry.Serial))
	}
	assert.ElementsMatch(t, wantIndex, gotIndex)
}

func assertPairStreamsEquivalent(t *testing.T, want, got *pki.PKI) {
	t.Helper()
	wantPairs := collectPairs(t, want)
	gotPairs := collectPairs(t, got)

	wantIDs := make([]string, 0, len(wantPairs))
	gotIDs := make([]string, 0, len(gotPairs))
	for _, pair := range wantPairs {
		serial, err := pair.Serial()
		require.NoError(t, err)
		wantIDs = append(wantIDs, pair.Name+":"+storage.HexSerial(serial))
	}
	for _, pair := range gotPairs {
		serial, err := pair.Serial()
		require.NoError(t, err)
		gotIDs = append(gotIDs, pair.Name+":"+storage.HexSerial(serial))
	}
	assert.ElementsMatch(t, wantIDs, gotIDs)
}

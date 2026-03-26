package pki_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
)

type cleaningKeyStorage struct {
	storage.KeyStorage
	cleaned map[string]bool
	err     error
}

func mustSerial(t *testing.T, pair *cert.Pair) *big.Int {
	t.Helper()
	serial, err := pair.Serial()
	require.NoError(t, err)
	return new(big.Int).Set(serial)
}

func (c *cleaningKeyStorage) CleanOrphans(knownSerials map[string]bool) error {
	c.cleaned = make(map[string]bool, len(knownSerials))
	for k, v := range knownSerials {
		c.cleaned[k] = v
	}
	return c.err
}

func TestClean_PassesKnownSerialsToCleaner(t *testing.T) {
	innerKS, cs, idx, sp, crl := memory.New()
	ks := &cleaningKeyStorage{KeyStorage: innerKS}
	pk := mustNewPKI(t, pki.Config{NoPass: true, SequentialSerial: true}, ks, cs, idx, sp, crl)

	caPair, err := pk.BuildCA()
	require.NoError(t, err)
	clientPair, err := pk.BuildClientFull("client1")
	require.NoError(t, err)

	require.NoError(t, pk.Clean())
	assert.Equal(t, map[string]bool{
		storage.HexSerial(mustSerial(t, caPair)):     true,
		storage.HexSerial(mustSerial(t, clientPair)): true,
	}, ks.cleaned)
}

func TestClean_NoOpWhenStorageDoesNotImplementCleaner(t *testing.T) {
	pk := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, pk)
	_, err := pk.BuildClientFull("client1")
	require.NoError(t, err)
	require.NoError(t, pk.Clean())
}

func TestClean_PropagatesCleanerError(t *testing.T) {
	innerKS, cs, idx, sp, crl := memory.New()
	ks := &cleaningKeyStorage{KeyStorage: innerKS, err: errors.New("clean failed")}
	pk := mustNewPKI(t, pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	buildTestCA(t, pk)

	err := pk.Clean()
	require.EqualError(t, err, "clean failed")
}

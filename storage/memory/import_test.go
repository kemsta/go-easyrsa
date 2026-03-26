package memory_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
)

func TestMemoryReplacePairs_ReplacesStateAndClonesInput(t *testing.T) {
	srcKS, _, _, _, _, srcPK := newMemoryPKI(t)
	_, err := srcPK.BuildCA()
	require.NoError(t, err)
	pair1, err := srcPK.BuildClientFull("client1")
	require.NoError(t, err)
	pair2, err := srcPK.BuildClientFull("client2")
	require.NoError(t, err)
	sourcePairs := collectExportedPairs(t, srcKS)

	dstKS, _, _, _, _ := memory.New()
	require.NoError(t, dstKS.ReplacePairs(func(yield func(*cert.Pair) error) error {
		for i, pair := range sourcePairs {
			if i == 1 {
				require.NoError(t, yield(nil))
			}
			if err := yield(pair); err != nil {
				return err
			}
		}
		return nil
	}))

	sourcePairs[0].CertPEM[0] ^= 0xFF
	sourcePairs[0].KeyPEM[0] ^= 0xFF

	gotPairs := collectExportedPairs(t, dstKS)
	assert.Equal(t, pairIDs(t, collectExportedPairs(t, srcKS)), pairIDs(t, gotPairs))

	got1, err := dstKS.GetBySerial(mustSerial(t, pair1))
	require.NoError(t, err)
	assert.Equal(t, pair1.Name, got1.Name)

	got2, err := dstKS.GetBySerial(mustSerial(t, pair2))
	require.NoError(t, err)
	assert.Equal(t, pair2.Name, got2.Name)
}

func TestMemoryReplaceAllAndSetNext_CloneInputs(t *testing.T) {
	_, _, idx, sp, _ := memory.New()

	serial := big.NewInt(7)
	entries := []storage.IndexEntry{{
		Status:    storage.StatusValid,
		Serial:    serial,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Subject:   pkixName("client1"),
	}}
	require.NoError(t, idx.ReplaceAll(entries))
	serial.SetInt64(99)
	entries[0].Serial.SetInt64(100)

	got, err := idx.Query(storage.IndexFilter{})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Zero(t, got[0].Serial.Cmp(big.NewInt(7)))

	next := big.NewInt(50)
	require.NoError(t, sp.SetNext(next))
	next.SetInt64(1)
	gotNext, err := sp.Next()
	require.NoError(t, err)
	assert.Zero(t, gotNext.Cmp(big.NewInt(50)))
}

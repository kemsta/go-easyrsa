package fs_test

import (
	"crypto/x509/pkix"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	fs "github.com/kemsta/go-easyrsa/v2/storage/fs"
)

func TestFSReplacePairs_ImportsStreamAndPreservesLatestNamedCert(t *testing.T) {
	sourceDir, sourcePK := newFSPKI(t)
	_, err := sourcePK.BuildCA()
	require.NoError(t, err)
	oldPair, err := sourcePK.BuildClientFull("client1", pki.WithDays(365))
	require.NoError(t, err)
	newPair, err := sourcePK.Renew("client1", pki.WithDays(730))
	require.NoError(t, err)

	sourceKS := fs.NewKeyStorage(sourceDir, "ca")
	sourcePairs := collectExportedPairs(t, sourceKS)
	require.Len(t, sourcePairs, 3)

	targetDir := t.TempDir()
	require.NoError(t, fs.InitDirs(targetDir))
	targetKS := fs.NewKeyStorage(targetDir, "ca")
	require.NoError(t, targetKS.ReplacePairs(func(yield func(*cert.Pair) error) error {
		for _, pair := range sourcePairs {
			if err := yield(pair); err != nil {
				return err
			}
		}
		return nil
	}))

	last, err := targetKS.GetLastByName("client1")
	require.NoError(t, err)
	assert.Zero(t, mustSerial(t, last).Cmp(mustSerial(t, newPair)))

	byOldSerial, err := targetKS.GetBySerial(mustSerial(t, oldPair))
	require.NoError(t, err)
	assert.Equal(t, "client1", byOldSerial.Name)
	byNewSerial, err := targetKS.GetBySerial(mustSerial(t, newPair))
	require.NoError(t, err)
	assert.Equal(t, "client1", byNewSerial.Name)

	all, err := targetKS.GetAll()
	require.NoError(t, err)
	assert.Equal(t, pairIDs(t, sourcePairs), pairIDs(t, all))
}

func TestFSSetNext_ValidationAndPersistence(t *testing.T) {
	dir, _ := newFSPKI(t)
	sp := fs.NewSerialProvider(dir)

	assert.Error(t, sp.SetNext(nil))
	assert.Error(t, sp.SetNext(big.NewInt(0)))

	require.NoError(t, sp.SetNext(big.NewInt(80)))
	next, err := sp.Next()
	require.NoError(t, err)
	assert.Zero(t, next.Cmp(big.NewInt(80)))

	sp2 := fs.NewSerialProvider(dir)
	next, err = sp2.Next()
	require.NoError(t, err)
	assert.Zero(t, next.Cmp(big.NewInt(81)))
}

func TestFSReplaceAll_HappyPath(t *testing.T) {
	dir, _ := newFSPKI(t)
	db := fs.NewIndexDB(dir)
	entries := []storage.IndexEntry{{
		Status: storage.StatusValid,
		Serial: big.NewInt(7),
		Subject: pkix.Name{CommonName: "client1"},
	}}
	require.NoError(t, db.ReplaceAll(entries))

	got, err := db.Query(storage.IndexFilter{})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Zero(t, got[0].Serial.Cmp(big.NewInt(7)))
}

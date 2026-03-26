package fs_test

import (
	"crypto/x509/pkix"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	fs "github.com/kemsta/go-easyrsa/v2/storage/fs"
)

func TestFSExportPairs_SortsBySerialAndUsesStorageNames(t *testing.T) {
	dir := t.TempDir()
	pk, err := pki.NewWithFS(dir, pki.Config{
		NoPass:           true,
		SequentialSerial: true,
		DNMode:           pki.DNModeOrg,
		SubjTemplate:     pkix.Name{Organization: []string{"Acme Corp"}},
	})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	serverPair, err := pk.BuildServerFull("server1", pki.WithSubjectOverride(pkix.Name{
		CommonName:   "VPN Server",
		Organization: []string{"Acme Corp"},
	}))
	require.NoError(t, err)
	clientPair, err := pk.BuildClientFull("client2")
	require.NoError(t, err)

	ks := fs.NewKeyStorage(dir, "ca")
	exported := collectExportedPairs(t, ks)
	require.Len(t, exported, 3)
	assert.Equal(t, []string{"ca", "server1", "client2"}, []string{exported[0].Name, exported[1].Name, exported[2].Name})
	assert.Zero(t, mustSerial(t, exported[1]).Cmp(mustSerial(t, serverPair)))
	assert.Zero(t, mustSerial(t, exported[2]).Cmp(mustSerial(t, clientPair)))
}

func TestFSExportPairs_FallsBackToNamedPairsWhenSerialIndexMissing(t *testing.T) {
	sourceDir, pk := newFSPKI(t)
	caPair, err := pk.BuildCA()
	require.NoError(t, err)
	clientPair, err := pk.BuildClientFull("client1")
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "issued"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "private"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.crt"), caPair.CertPEM, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "private", "ca.key"), caPair.KeyPEM, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "issued", "client1.crt"), clientPair.CertPEM, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "private", "client1.key"), clientPair.KeyPEM, 0600))
	_ = sourceDir

	ks := fs.NewKeyStorage(dir, "ca")
	exported := collectExportedPairs(t, ks)
	require.Len(t, exported, 2)
	assert.ElementsMatch(t, []string{"ca", "client1"}, []string{exported[0].Name, exported[1].Name})
}

func TestFSExportPairs_StopsOnYieldError(t *testing.T) {
	dir, pk := newFSPKI(t)
	_, err := pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("client1")
	require.NoError(t, err)

	ks := fs.NewKeyStorage(dir, "ca")
	wantErr := errors.New("stop")
	calls := 0
	err = ks.ExportPairs(func(*cert.Pair) error {
		calls++
		return wantErr
	})
	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, 1, calls)
}

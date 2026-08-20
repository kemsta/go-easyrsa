package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
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

func TestImportSnapshotPersistsValidatedCRLArtifacts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fixture := testutil.WriteLegacyFixture(t, dir)
	source, err := pki.NewWithLegacyFSRO(dir, pki.Config{})
	require.NoError(t, err)
	snapshot, err := source.ExportSnapshot()
	require.NoError(t, err)

	backend := memory.NewBackend()
	target, err := pki.New(pki.Config{CAName: snapshot.CAName}, backend)
	require.NoError(t, err)
	require.NoError(t, target.ImportSnapshot(snapshot, source.ExportPairs))
	block, _ := pem.Decode(snapshot.CRLPEM)
	require.NotNil(t, block)
	require.NoError(t, backend.View(func(components storage.Components) error {
		pemArtifact, err := components.Artifacts().GetArtifact("crl.pem")
		require.NoError(t, err)
		require.Equal(t, snapshot.CRLPEM, pemArtifact.Data)
		derArtifact, err := components.Artifacts().GetArtifact("crl.der")
		require.NoError(t, err)
		require.Equal(t, block.Bytes, derArtifact.Data)
		_, err = x509.ParseRevocationList(derArtifact.Data)
		return err
	}))

	malformedBackend := memory.NewBackend()
	malformedTarget, err := pki.New(pki.Config{CAName: "ca"}, malformedBackend)
	require.NoError(t, err)
	malformed := &pki.Snapshot{CAName: "ca", CRLPEM: fixture.CAPair.CertPEM}
	err = malformedTarget.ImportSnapshot(malformed, func(func(*cert.Pair) error) error { return nil })
	require.Error(t, err)
	require.NoError(t, malformedBackend.View(func(components storage.Components) error {
		_, err := components.Artifacts().GetArtifact("crl.pem")
		require.ErrorIs(t, err, storage.ErrNotFound)
		return nil
	}))
}

func TestImportSnapshotRejectsCRLSignedByAnotherCA(t *testing.T) {
	t.Parallel()

	first, err := pki.NewWithMemory(pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = first.BuildCA()
	require.NoError(t, err)
	_, err = first.GenCRL()
	require.NoError(t, err)
	firstSnapshot, err := first.ExportSnapshot()
	require.NoError(t, err)

	second, err := pki.NewWithMemory(pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = second.BuildCA()
	require.NoError(t, err)
	secondSnapshot, err := second.ExportSnapshot()
	require.NoError(t, err)
	secondSnapshot.CRLPEM = firstSnapshot.CRLPEM

	backend := memory.NewBackend()
	target, err := pki.New(pki.Config{NoPass: true, CAName: secondSnapshot.CAName}, backend)
	require.NoError(t, err)
	err = target.ImportSnapshot(secondSnapshot, second.ExportPairs)
	require.Error(t, err)
	_, err = target.ShowCA()
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestSnapshotRoundTripPreservesLifecycleLocations(t *testing.T) {
	t.Parallel()

	source, err := pki.NewWithFS(filepath.Join(t.TempDir(), "source"), pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = source.BuildCA()
	require.NoError(t, err)
	_, err = source.BuildClientFull("expired")
	require.NoError(t, err)
	require.NoError(t, source.Expire("expired"))
	_, err = source.BuildClientFull("renewed", pki.WithCertModifier(func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(1000)
	}))
	require.NoError(t, err)
	_, err = source.Renew("renewed", pki.WithCertModifier(func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(10)
	}))
	require.NoError(t, err)
	_, err = source.BuildClientFull("revoked", pki.WithCertModifier(func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(2000)
	}))
	require.NoError(t, err)
	require.NoError(t, source.RevokeIssued("revoked", cert.ReasonUnspecified))
	currentRevoked, err := source.BuildClientFull("revoked", pki.WithCertModifier(func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(20)
	}))
	require.NoError(t, err)

	snapshot, err := source.ExportSnapshot()
	require.NoError(t, err)
	require.Len(t, snapshot.Lifecycle.Expired, 1)
	require.Len(t, snapshot.Lifecycle.Renewed, 1)
	require.Len(t, snapshot.Lifecycle.Revoked, 1)

	for _, targetCase := range lifecycleBackends() {
		t.Run(targetCase.name, func(t *testing.T) {
			backend, _ := targetCase.create(t)
			require.NoError(t, backend.EnsureLayout())
			target, err := pki.New(pki.Config{NoPass: true, SequentialSerial: true, CAName: snapshot.CAName}, backend)
			require.NoError(t, err)
			require.NoError(t, target.ImportSnapshot(snapshot, source.ExportPairs))
			roundTrip, err := target.ExportSnapshot()
			require.NoError(t, err)
			assertSnapshotEquivalent(t, snapshot, roundTrip)
			importedCurrent, err := target.ShowCert("revoked")
			require.NoError(t, err)
			require.Equal(t, currentRevoked.CertPEM, importedCurrent.CertPEM)
			require.Equal(t, currentRevoked.KeyPEM, importedCurrent.KeyPEM)
			_, err = target.Renew("renewed")
			require.ErrorIs(t, err, storage.ErrConflict)
			require.NoError(t, target.RevokeExpired("expired", cert.ReasonCessationOfOperation))
		})
	}
}

func TestImportSnapshotRejectsNonemptyTargetBeforeConsumingStream(t *testing.T) {
	t.Parallel()

	source, err := pki.NewWithMemory(pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = source.BuildCA()
	require.NoError(t, err)
	snapshot, err := source.ExportSnapshot()
	require.NoError(t, err)

	backend := memory.NewBackend()
	target, err := pki.New(pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024}, backend)
	require.NoError(t, err)
	_, err = target.BuildCA()
	require.NoError(t, err)
	_, err = target.GenCRL()
	require.NoError(t, err)
	before, err := target.ExportSnapshot()
	require.NoError(t, err)
	streamCalled := false
	err = target.ImportSnapshot(snapshot, func(func(*cert.Pair) error) error {
		streamCalled = true
		return nil
	})
	require.ErrorIs(t, err, storage.ErrConflict)
	require.False(t, streamCalled)
	after, err := target.ExportSnapshot()
	require.NoError(t, err)
	assertSnapshotEquivalent(t, before, after)
}

func TestImportSnapshot_MemoryPreservesHistoryAndStatuses(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteLegacyFixture(t, dir)

	source, err := pki.NewWithLegacyFSRO(dir, pki.Config{})
	require.NoError(t, err)
	snapshot, err := source.ExportSnapshot()
	require.NoError(t, err)

	ks, cs, idx, sp, crl := memory.New()
	target := mustNewPKI(t, pki.Config{CAName: snapshot.CAName}, ks, cs, idx, sp, crl)
	require.NoError(t, target.ImportSnapshot(snapshot, source.ExportPairs))

	pairs, err := ks.GetByName("client1")
	require.NoError(t, err)
	assert.Len(t, pairs, 2)

	exported, err := target.ExportSnapshot()
	require.NoError(t, err)
	assertSnapshotEquivalent(t, snapshot, exported)
	assertPairStreamsEquivalent(t, source, target)
}

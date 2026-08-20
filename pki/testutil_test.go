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
)

type testBackend struct{ components *testComponents }

type testComponents struct {
	keys    storage.KeyStorage
	csrs    storage.CSRStorage
	index   storage.IndexDB
	serials storage.SerialProvider
	crls    storage.CRLHolder
}

func newTestBackend(keys storage.KeyStorage, csrs storage.CSRStorage, index storage.IndexDB, serials storage.SerialProvider, crls storage.CRLHolder) *testBackend {
	return &testBackend{components: &testComponents{keys: keys, csrs: csrs, index: index, serials: serials, crls: crls}}
}

func (b *testBackend) EnsureLayout() error   { return nil }
func (b *testBackend) Initialize(bool) error { return nil }
func (b *testBackend) ReadOnly() bool        { return false }
func (b *testBackend) View(fn func(storage.Components) error) error {
	return fn(b.components)
}
func (b *testBackend) Update(fn func(storage.Components) error) error {
	return fn(b.components)
}

func (c *testComponents) Empty() (bool, error) {
	pairs, err := c.keys.GetAll()
	if err != nil {
		return false, err
	}
	requests, err := c.csrs.ListCSRs()
	if err != nil && !errors.Is(err, storage.ErrReadOnly) {
		return false, err
	}
	entries, err := c.index.Query(storage.IndexFilter{})
	if err != nil {
		return false, err
	}
	crl, err := c.crls.Get()
	if err != nil {
		return false, err
	}
	return len(pairs) == 0 && len(requests) == 0 && len(entries) == 0 && len(crl.Raw) == 0, nil
}
func (c *testComponents) Keys() storage.KeyStorage            { return c.keys }
func (c *testComponents) CSRs() storage.CSRStorage            { return c.csrs }
func (c *testComponents) Index() storage.IndexDB              { return c.index }
func (c *testComponents) Serials() storage.SerialProvider     { return c.serials }
func (c *testComponents) CRLs() storage.CRLHolder             { return c.crls }
func (c *testComponents) Artifacts() storage.ArtifactStorage  { return testArtifactStorage{} }
func (c *testComponents) Lifecycle() storage.LifecycleStorage { return testLifecycleStorage{} }

type testArtifactStorage struct{}

func (testArtifactStorage) PutArtifact(storage.Artifact) error { return nil }
func (testArtifactStorage) GetArtifact(string) (storage.Artifact, error) {
	return storage.Artifact{}, storage.ErrNotFound
}
func (testArtifactStorage) DeleteArtifact(string) error { return storage.ErrNotFound }

type testLifecycleStorage struct{}

func (testLifecycleStorage) MoveIssuedToExpired(string, *big.Int) error { return storage.ErrNotFound }
func (testLifecycleStorage) MoveIssuedToRenewed(string, *big.Int) error { return storage.ErrNotFound }
func (testLifecycleStorage) MoveIssuedToRevoked(string, *big.Int) error {
	return storage.ErrNotFound
}
func (testLifecycleStorage) MoveExpiredToRevoked(string, *big.Int) error {
	return storage.ErrNotFound
}
func (testLifecycleStorage) MoveRenewedToRevoked(string, *big.Int) error {
	return storage.ErrNotFound
}
func (testLifecycleStorage) ExportState() (storage.LifecycleState, error) {
	return storage.LifecycleState{}, nil
}
func (testLifecycleStorage) ReplaceState(storage.LifecycleState) error { return nil }
func (testLifecycleStorage) GetExpiredCertificate(string) ([]byte, error) {
	return nil, storage.ErrNotFound
}
func (testLifecycleStorage) GetRenewedCertificate(string) ([]byte, error) {
	return nil, storage.ErrNotFound
}
func (testLifecycleStorage) ListRenewed() ([]storage.RenewalArchive, error) {
	return nil, nil
}

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
	assert.Equal(t, want.Current, got.Current)
	assert.Equal(t, want.Lifecycle, got.Lifecycle)

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

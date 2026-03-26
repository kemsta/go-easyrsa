package memory_test

import (
	"crypto/x509/pkix"
	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"sort"
	"testing"
	"time"
)

func TestMemoryIndexDB_QueryReturnsIndependentSerials(t *testing.T) {
	_, _, idx, sp, _ := memory.New()

	serial, err := sp.Next()
	require.NoError(t, err)
	originalSerial := new(big.Int).Set(serial) // save a copy before storing

	require.NoError(t, idx.Record(storage.IndexEntry{
		Status:    storage.StatusValid,
		Serial:    serial,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}))

	// First Query: get the entry and mutate its Serial in place.
	results, err := idx.Query(storage.IndexFilter{})
	require.NoError(t, err)
	require.Len(t, results, 1)

	results[0].Serial.SetInt64(0) // destructive mutation via shared pointer

	// Second Query: the stored entry must still carry the original serial.
	results2, err := idx.Query(storage.IndexFilter{})
	require.NoError(t, err)
	require.Len(t, results2, 1)

	assert.Equal(t, originalSerial, results2[0].Serial,
		"Query returned a *big.Int that aliases the internal store; "+
			"mutating results[0].Serial corrupted the IndexDB entry — "+
			"Query must return a deep copy of each Serial")
}

func TestMemoryIndexDB_RecordStoresIndependentSerial(t *testing.T) {
	_, _, idx, sp, _ := memory.New()

	serial, err := sp.Next()
	require.NoError(t, err)
	originalValue := new(big.Int).Set(serial)

	require.NoError(t, idx.Record(storage.IndexEntry{
		Status:    storage.StatusValid,
		Serial:    serial,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}))

	// Mutate the serial AFTER recording — simulates a caller reusing a *big.Int.
	serial.SetInt64(999)

	results, err := idx.Query(storage.IndexFilter{})
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, originalValue, results[0].Serial,
		"Record stored the caller's *big.Int by pointer; "+
			"mutating serial after Record changed the stored entry — "+
			"Record must store a deep copy of Serial")
}

func TestMemoryKeyStorage_KeyOnlyPutDoesNotHideExistingCert(t *testing.T) {
	ks, _, _, _, _ := memory.New()

	// Store a cert+key pair.
	certPair := &cert.Pair{
		Name:    "entity",
		CertPEM: []byte("fake-cert-pem"),
		KeyPEM:  []byte("original-key-pem"),
	}
	require.NoError(t, ks.Put(certPair))

	// Simulate GenReq: store a key-only pair for the same name (no CertPEM).
	keyPair := &cert.Pair{
		Name:   "entity",
		KeyPEM: []byte("new-key-pem"),
	}
	require.NoError(t, ks.Put(keyPair))

	// GetLastByName must return a cert-bearing pair, not the key-only pair.
	got, err := ks.GetLastByName("entity")
	require.NoError(t, err)

	assert.NotNil(t, got.CertPEM,
		"GetLastByName returned a key-only pair after a key-only Put; "+
			"the existing certificate was hidden by the appended key-only entry. "+
			"Key-only Puts must update the existing pair's key in place, "+
			"not append a new key-only entry.")
}
func newMemoryPKI(t *testing.T) (*memory.KeyStorage, *memory.CSRStorage, *memory.IndexDB, *memory.SerialProvider, *memory.CRLHolder, *pki.PKI) {
	t.Helper()
	ks, cs, idx, sp, crl := memory.New()
	pk, err := pki.New(pki.Config{NoPass: true, SequentialSerial: true}, ks, cs, idx, sp, crl)
	require.NoError(t, err)
	return ks, cs, idx, sp, crl, pk
}

func mustSerial(t *testing.T, pair *cert.Pair) *big.Int {
	t.Helper()
	serial, err := pair.Serial()
	require.NoError(t, err)
	return new(big.Int).Set(serial)
}

func collectExportedPairs(t *testing.T, exporter storage.PairExporter) []*cert.Pair {
	t.Helper()
	var pairs []*cert.Pair
	err := exporter.ExportPairs(func(pair *cert.Pair) error {
		cp := &cert.Pair{Name: pair.Name}
		if pair.CertPEM != nil {
			cp.CertPEM = append([]byte(nil), pair.CertPEM...)
		}
		if pair.KeyPEM != nil {
			cp.KeyPEM = append([]byte(nil), pair.KeyPEM...)
		}
		pairs = append(pairs, cp)
		return nil
	})
	require.NoError(t, err)
	return pairs
}

func pairIDs(t *testing.T, pairs []*cert.Pair) []string {
	t.Helper()
	ids := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		serial, err := pair.Serial()
		require.NoError(t, err)
		ids = append(ids, pair.Name+":"+storage.HexSerial(serial))
	}
	sort.Strings(ids)
	return ids
}
func TestMemoryKeyStorage_PublicCRUDAndNotFound(t *testing.T) {
	ks, _, _, _, _, pk := newMemoryPKI(t)

	_, err := pk.BuildCA()
	require.NoError(t, err)
	client1, err := pk.BuildClientFull("client1")
	require.NoError(t, err)
	client2, err := pk.BuildClientFull("client2")
	require.NoError(t, err)

	pairs, err := ks.GetByName("client1")
	require.NoError(t, err)
	require.Len(t, pairs, 1)
	assert.Equal(t, "client1", pairs[0].Name)

	pairBySerial, err := ks.GetBySerial(mustSerial(t, client1))
	require.NoError(t, err)
	assert.Equal(t, client1.Name, pairBySerial.Name)

	all, err := ks.GetAll()
	require.NoError(t, err)
	assert.ElementsMatch(t,
		[]string{"ca", "client1", "client2"},
		[]string{all[0].Name, all[1].Name, all[2].Name},
	)

	require.NoError(t, ks.DeleteBySerial(mustSerial(t, client2)))
	_, err = ks.GetBySerial(mustSerial(t, client2))
	assert.ErrorIs(t, err, storage.ErrNotFound)
	_, err = ks.GetByName("client2")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	require.NoError(t, ks.DeleteByName("client1"))
	_, err = ks.GetByName("client1")
	assert.ErrorIs(t, err, storage.ErrNotFound)
	_, err = ks.GetBySerial(mustSerial(t, client1))
	assert.ErrorIs(t, err, storage.ErrNotFound)

	_, err = ks.GetByName("missing")
	assert.ErrorIs(t, err, storage.ErrNotFound)
	_, err = ks.GetLastByName("missing")
	assert.ErrorIs(t, err, storage.ErrNotFound)
	_, err = ks.GetBySerial(big.NewInt(999))
	assert.ErrorIs(t, err, storage.ErrNotFound)
	assert.ErrorIs(t, ks.DeleteByName("missing"), storage.ErrNotFound)
	assert.ErrorIs(t, ks.DeleteBySerial(big.NewInt(999)), storage.ErrNotFound)
}

func TestMemoryCSRStorage_PublicCRUD(t *testing.T) {
	_, cs, _, _, _, _ := newMemoryPKI(t)

	empty, err := cs.Empty()
	require.NoError(t, err)
	assert.True(t, empty)

	require.NoError(t, cs.PutCSR("client1", []byte("csr-1")))
	require.NoError(t, cs.PutCSR("client2", []byte("csr-2")))

	csr, err := cs.GetCSR("client1")
	require.NoError(t, err)
	assert.Equal(t, []byte("csr-1"), csr)

	names, err := cs.ListCSRs()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"client1", "client2"}, names)

	require.NoError(t, cs.DeleteCSR("client1"))
	_, err = cs.GetCSR("client1")
	assert.ErrorIs(t, err, storage.ErrNotFound)
	assert.ErrorIs(t, cs.DeleteCSR("client1"), storage.ErrNotFound)
}

func TestMemoryIndexDB_UpdateRecordAndQuery(t *testing.T) {
	_, _, idx, sp, _, _ := newMemoryPKI(t)
	serial1, err := sp.Next()
	require.NoError(t, err)
	serial2, err := sp.Next()
	require.NoError(t, err)
	serial3, err := sp.Next()
	require.NoError(t, err)

	expires := time.Now().Add(24 * time.Hour)
	require.NoError(t, idx.Record(storage.IndexEntry{
		Status:    storage.StatusValid,
		Serial:    serial1,
		ExpiresAt: expires,
		Subject:   pkixName("client1"),
	}))
	require.NoError(t, idx.Record(storage.IndexEntry{
		Status:    storage.StatusValid,
		Serial:    serial2,
		ExpiresAt: expires,
		Subject:   pkixName("client2"),
	}))

	revokedAt := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, idx.Update(serial1, storage.StatusRevoked, revokedAt, cert.ReasonKeyCompromise))

	require.NoError(t, idx.RecordAndUpdate(storage.IndexEntry{
		Status:    storage.StatusValid,
		Serial:    serial3,
		ExpiresAt: expires,
		Subject:   pkixName("client3"),
	}, serial2, storage.StatusExpired, time.Time{}, cert.ReasonUnspecified))

	all, err := idx.Query(storage.IndexFilter{})
	require.NoError(t, err)
	require.Len(t, all, 3)

	revokedStatus := storage.StatusRevoked
	revoked, err := idx.Query(storage.IndexFilter{Status: &revokedStatus})
	require.NoError(t, err)
	require.Len(t, revoked, 1)
	assert.Zero(t, revoked[0].Serial.Cmp(serial1))
	assert.Equal(t, cert.ReasonKeyCompromise, revoked[0].RevocationReason)

	expiredStatus := storage.StatusExpired
	expired, err := idx.Query(storage.IndexFilter{Status: &expiredStatus})
	require.NoError(t, err)
	require.Len(t, expired, 1)
	assert.Zero(t, expired[0].Serial.Cmp(serial2))

	byName, err := idx.Query(storage.IndexFilter{Name: "client3"})
	require.NoError(t, err)
	require.Len(t, byName, 1)
	assert.Zero(t, byName[0].Serial.Cmp(serial3))

	assert.ErrorIs(t, idx.Update(big.NewInt(999), storage.StatusRevoked, revokedAt, cert.ReasonKeyCompromise), storage.ErrNotFound)

	serial4, err := sp.Next()
	require.NoError(t, err)
	require.NoError(t, idx.RecordAndUpdate(storage.IndexEntry{
		Status:    storage.StatusValid,
		Serial:    serial4,
		ExpiresAt: expires,
		Subject:   pkixName("orphan"),
	}, big.NewInt(999), storage.StatusRevoked, revokedAt, cert.ReasonKeyCompromise))

	byName, err = idx.Query(storage.IndexFilter{Name: "orphan"})
	require.NoError(t, err)
	require.Len(t, byName, 1)
	assert.Zero(t, byName[0].Serial.Cmp(serial4))
}

func TestMemorySerialProvider_SetNext(t *testing.T) {
	_, _, _, sp, _, _ := newMemoryPKI(t)

	assert.Error(t, sp.SetNext(nil))
	assert.Error(t, sp.SetNext(big.NewInt(0)))

	require.NoError(t, sp.SetNext(big.NewInt(42)))
	next, err := sp.Next()
	require.NoError(t, err)
	assert.Zero(t, next.Cmp(big.NewInt(42)))

	next, err = sp.Next()
	require.NoError(t, err)
	assert.Zero(t, next.Cmp(big.NewInt(43)))
}

func TestMemoryCRLHolder_GetBehavior(t *testing.T) {
	_, _, _, _, crl, pk := newMemoryPKI(t)

	list, err := crl.Get()
	require.NoError(t, err)
	assert.Empty(t, list.RevokedCertificateEntries)

	_, err = pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("client1")
	require.NoError(t, err)
	require.NoError(t, pk.Revoke("client1", cert.ReasonKeyCompromise))
	crlPEM, err := pk.GenCRL()
	require.NoError(t, err)

	require.NoError(t, crl.Put(crlPEM))
	list, err = crl.Get()
	require.NoError(t, err)
	require.Len(t, list.RevokedCertificateEntries, 1)
	assert.Equal(t, 1, list.RevokedCertificateEntries[0].ReasonCode)

	require.NoError(t, crl.Put([]byte("not a pem")))
	list, err = crl.Get()
	require.NoError(t, err)
	assert.Empty(t, list.RevokedCertificateEntries)
}

func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }

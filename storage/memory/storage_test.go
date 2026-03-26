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

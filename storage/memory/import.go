package memory

import (
	"fmt"
	"math/big"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// ReplacePairs imports a full pair stream while preserving history-by-name.
func (ks *KeyStorage) ReplacePairs(stream storage.PairStream) error {
	ks.s.mu.Lock()
	defer ks.s.mu.Unlock()

	ks.s.pairs = make(map[string][]*cert.Pair)
	ks.s.bySerial = make(map[string]*cert.Pair)
	ks.s.unavailable = make(map[string]bool)

	return stream(func(pair *cert.Pair) error {
		if pair == nil {
			return nil
		}
		if err := storage.ValidateEntityName(pair.Name); err != nil {
			return err
		}
		cp := clonePair(pair)
		ks.s.pairs[cp.Name] = append(ks.s.pairs[cp.Name], cp)
		if cp.CertPEM != nil {
			if serial, err := cp.Serial(); err == nil {
				ks.s.bySerial[hexSerial(serial)] = cp
			}
		}
		return nil
	})
}

// ReplaceAll replaces the full in-memory index with the supplied entries.
func (db *IndexDB) ReplaceAll(entries []storage.IndexEntry) error {
	db.s.mu.Lock()
	defer db.s.mu.Unlock()
	db.s.entries = make([]storage.IndexEntry, len(entries))
	for i, entry := range entries {
		db.s.entries[i] = cloneIndexEntry(entry)
	}
	return nil
}

// SetNext sets the next serial that will be returned by Next().
func (sp *SerialProvider) SetNext(next *big.Int) error {
	sp.s.mu.Lock()
	defer sp.s.mu.Unlock()
	if next == nil || next.Sign() <= 0 {
		return fmt.Errorf("storage/memory: next serial must be positive")
	}
	sp.s.serial = new(big.Int).Set(next)
	return nil
}

var (
	_ storage.PairReplacer       = (*KeyStorage)(nil)
	_ storage.IndexReplacer      = (*IndexDB)(nil)
	_ storage.SerialSetter       = (*SerialProvider)(nil)
	_ storage.OwnershipValidator = (*KeyStorage)(nil)
	_ storage.OwnershipValidator = (*CSRStorage)(nil)
	_ storage.OwnershipValidator = (*IndexDB)(nil)
	_ storage.OwnershipValidator = (*SerialProvider)(nil)
	_ storage.OwnershipValidator = (*CRLHolder)(nil)
)

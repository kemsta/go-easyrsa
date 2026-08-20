// Package memory provides in-memory implementations of all storage interfaces.
// Intended for unit testing — no persistence across process restarts.
package memory

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// store holds all shared in-memory state.
type store struct {
	mu                    sync.RWMutex
	pairs                 map[string][]*cert.Pair // name → ordered history (latest last)
	bySerial              map[string]*cert.Pair   // uppercase hex serial → pair
	csrs                  map[string][]byte       // name → CSR PEM
	pendingKeys           map[string][]byte       // name → key for an unsigned request
	entries               []storage.IndexEntry    // index DB rows
	crlPEM                []byte                  // CRL PEM, nil if none
	serial                *big.Int                // next serial counter
	artifacts             map[string]storage.Artifact
	expired               map[string][]byte
	renewed               map[string][]byte
	renewedBySerial       map[string][]byte // serial → historical renewed certificate PEM
	revokedCerts          map[string][]byte // serial → certificate PEM
	revokedKeys           map[string][]byte // serial → private key PEM
	revokedCSRs           map[string][]byte // serial → CSR PEM
	revokedNames          map[string]string // serial → storage entity name
	revokedAssetsArchived map[string]bool   // serial → key/CSR moved with certificate
	unavailable           map[string]bool   // no certificate in issued/ for this name
}

func newStore() *store {
	return &store{
		pairs:                 make(map[string][]*cert.Pair),
		bySerial:              make(map[string]*cert.Pair),
		csrs:                  make(map[string][]byte),
		pendingKeys:           make(map[string][]byte),
		serial:                big.NewInt(1),
		artifacts:             make(map[string]storage.Artifact),
		expired:               make(map[string][]byte),
		renewed:               make(map[string][]byte),
		renewedBySerial:       make(map[string][]byte),
		revokedCerts:          make(map[string][]byte),
		revokedKeys:           make(map[string][]byte),
		revokedCSRs:           make(map[string][]byte),
		revokedNames:          make(map[string]string),
		revokedAssetsArchived: make(map[string]bool),
		unavailable:           make(map[string]bool),
	}
}

func (s *store) empty() bool {
	return len(s.pairs) == 0 && len(s.bySerial) == 0 && len(s.csrs) == 0 && len(s.pendingKeys) == 0 && len(s.entries) == 0 &&
		len(s.crlPEM) == 0 && len(s.artifacts) == 0 && len(s.expired) == 0 && len(s.renewed) == 0 && len(s.renewedBySerial) == 0 &&
		len(s.revokedCerts) == 0 && len(s.revokedKeys) == 0 && len(s.revokedCSRs) == 0 && len(s.revokedNames) == 0 && len(s.revokedAssetsArchived) == 0 &&
		s.serial != nil && s.serial.Cmp(big.NewInt(1)) == 0
}

// New creates all five storage implementations sharing the same in-memory state.
func New() (*KeyStorage, *CSRStorage, *IndexDB, *SerialProvider, *CRLHolder) {
	s := newStore()
	return &KeyStorage{s}, &CSRStorage{s}, &IndexDB{s}, &SerialProvider{s}, &CRLHolder{s}
}

// --- KeyStorage ---

// KeyStorage implements storage.KeyStorage in memory.
type KeyStorage struct{ s *store }

func (ks *KeyStorage) Empty() (bool, error) {
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()
	return ks.s.empty(), nil
}
func (ks *KeyStorage) Owned() (bool, error) { return true, nil }

func (ks *KeyStorage) Put(pair *cert.Pair) error {
	if pair == nil {
		return errors.New("storage/memory: nil certificate pair")
	}
	if err := storage.ValidateEntityName(pair.Name); err != nil {
		return err
	}
	ks.s.mu.Lock()
	defer ks.s.mu.Unlock()

	stored := clonePair(pair)
	if stored.CertPEM != nil {
		// Preserve prior serial-indexed certificates as history. A newly issued
		// certificate becomes the current named certificate.
		if stored.KeyPEM == nil {
			if pending := ks.s.pendingKeys[stored.Name]; pending != nil {
				stored.KeyPEM = cloneBytes(pending)
			} else {
				existing := ks.s.pairs[stored.Name]
				if len(existing) > 0 {
					stored.KeyPEM = cloneBytes(existing[len(existing)-1].KeyPEM)
				}
			}
		}
		existing := ks.s.pairs[stored.Name]
		switch {
		case len(existing) == 0:
			ks.s.pairs[stored.Name] = []*cert.Pair{stored}
		case existing[len(existing)-1].CertPEM == nil:
			existing[len(existing)-1] = stored
			ks.s.pairs[stored.Name] = existing
		case ks.s.unavailable[stored.Name]:
			ks.s.pairs[stored.Name] = append(existing, stored)
		default:
			if previousSerial, err := existing[len(existing)-1].Serial(); err == nil {
				delete(ks.s.bySerial, hexSerial(previousSerial))
			}
			existing[len(existing)-1] = stored
			ks.s.pairs[stored.Name] = existing
		}
		if serial, err := stored.Serial(); err == nil {
			ks.s.bySerial[hexSerial(serial)] = stored
		}
		delete(ks.s.pendingKeys, stored.Name)
		delete(ks.s.unavailable, stored.Name)
		return nil
	}

	// Keep the key for an unsigned request separate from archived certificate
	// history. For a current issued certificate, the filesystem-compatible key
	// view also changes immediately.
	ks.s.pendingKeys[stored.Name] = cloneBytes(stored.KeyPEM)
	existing := ks.s.pairs[stored.Name]
	if !ks.s.unavailable[stored.Name] && len(existing) > 0 {
		existing[len(existing)-1].KeyPEM = cloneBytes(stored.KeyPEM)
	} else if len(existing) == 0 {
		ks.s.pairs[stored.Name] = append(existing, stored)
	}
	return nil
}

func (ks *KeyStorage) GetByName(name string) ([]*cert.Pair, error) {
	if err := storage.ValidateEntityName(name); err != nil {
		return nil, err
	}
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()
	pairs := ks.s.pairs[name]
	if len(pairs) == 0 {
		return nil, storage.ErrNotFound
	}
	result := make([]*cert.Pair, len(pairs))
	for i, pair := range pairs {
		result[i] = clonePair(pair)
	}
	return result, nil
}

func (ks *KeyStorage) GetLastByName(name string) (*cert.Pair, error) {
	if err := storage.ValidateEntityName(name); err != nil {
		return nil, err
	}
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()
	if !ks.s.unavailable[name] {
		pairs := ks.s.pairs[name]
		if len(pairs) > 0 {
			return clonePair(pairs[len(pairs)-1]), nil
		}
	}
	var latestSerial *big.Int
	var latestKey string
	for serial, revokedName := range ks.s.revokedNames {
		if revokedName != name {
			continue
		}
		value := new(big.Int)
		if _, ok := value.SetString(serial, 16); !ok {
			continue
		}
		if latestSerial == nil || value.Cmp(latestSerial) > 0 {
			latestSerial = value
			latestKey = serial
		}
	}
	if latestSerial == nil {
		return nil, storage.ErrNotFound
	}
	return &cert.Pair{
		Name:    name,
		CertPEM: cloneBytes(ks.s.revokedCerts[latestKey]),
		KeyPEM:  cloneBytes(ks.s.revokedKeys[latestKey]),
	}, nil
}

func (ks *KeyStorage) GetPrivateKey(name string) ([]byte, error) {
	if err := storage.ValidateEntityName(name); err != nil {
		return nil, err
	}
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()
	if pending, ok := ks.s.pendingKeys[name]; ok {
		return cloneBytes(pending), nil
	}
	pairs := ks.s.pairs[name]
	if len(pairs) > 0 && pairs[len(pairs)-1].KeyPEM != nil {
		return cloneBytes(pairs[len(pairs)-1].KeyPEM), nil
	}
	return nil, storage.ErrNotFound
}

func (ks *KeyStorage) GetBySerial(serial *big.Int) (*cert.Pair, error) {
	if err := storage.ValidateSerial(serial); err != nil {
		return nil, err
	}
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()
	serialKey := hexSerial(serial)
	pair, ok := ks.s.bySerial[serialKey]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return ks.cloneHistoricalPair(pair, serialKey), nil
}

func (ks *KeyStorage) cloneHistoricalPair(pair *cert.Pair, serialKey string) *cert.Pair {
	cloned := clonePair(pair)
	cloned.KeyPEM = nil
	pairs := ks.s.pairs[pair.Name]
	if !ks.s.unavailable[pair.Name] && len(pairs) > 0 && pairs[len(pairs)-1] == pair {
		cloned.KeyPEM = cloneBytes(pair.KeyPEM)
	} else if ks.s.revokedAssetsArchived[serialKey] {
		cloned.KeyPEM = cloneBytes(ks.s.revokedKeys[serialKey])
	}
	return cloned
}

func (ks *KeyStorage) DeleteByName(name string) error {
	if err := storage.ValidateEntityName(name); err != nil {
		return err
	}
	ks.s.mu.Lock()
	defer ks.s.mu.Unlock()
	pairs, ok := ks.s.pairs[name]
	if !ok {
		return storage.ErrNotFound
	}
	for _, p := range pairs {
		if p.CertPEM != nil {
			if serial, err := p.Serial(); err == nil {
				delete(ks.s.bySerial, hexSerial(serial))
			}
		}
	}
	delete(ks.s.pairs, name)
	delete(ks.s.pendingKeys, name)
	delete(ks.s.unavailable, name)
	return nil
}

func (ks *KeyStorage) DeleteBySerial(serial *big.Int) error {
	if err := storage.ValidateSerial(serial); err != nil {
		return err
	}
	ks.s.mu.Lock()
	defer ks.s.mu.Unlock()
	key := hexSerial(serial)
	pair, ok := ks.s.bySerial[key]
	if !ok {
		return storage.ErrNotFound
	}
	delete(ks.s.bySerial, key)
	if pairs, ok := ks.s.pairs[pair.Name]; ok {
		for i, p := range pairs {
			if p == pair {
				ks.s.pairs[pair.Name] = append(pairs[:i], pairs[i+1:]...)
				break
			}
		}
	}
	return nil
}

func (ks *KeyStorage) GetAll() ([]*cert.Pair, error) {
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()
	var result []*cert.Pair
	for _, pairs := range ks.s.pairs {
		for _, pair := range pairs {
			serial, err := pair.Serial()
			if err != nil {
				result = append(result, clonePair(pair))
				continue
			}
			result = append(result, ks.cloneHistoricalPair(pair, hexSerial(serial)))
		}
	}
	return result, nil
}

// --- CSRStorage ---

// CSRStorage implements storage.CSRStorage in memory.
type CSRStorage struct{ s *store }

func (cs *CSRStorage) Empty() (bool, error) {
	cs.s.mu.RLock()
	defer cs.s.mu.RUnlock()
	return cs.s.empty(), nil
}
func (cs *CSRStorage) Owned() (bool, error) { return true, nil }

func (cs *CSRStorage) PutCSR(name string, csrPEM []byte) error {
	if err := storage.ValidateEntityName(name); err != nil {
		return err
	}
	cs.s.mu.Lock()
	defer cs.s.mu.Unlock()
	cs.s.csrs[name] = cloneBytes(csrPEM)
	return nil
}

func (cs *CSRStorage) GetCSR(name string) ([]byte, error) {
	if err := storage.ValidateEntityName(name); err != nil {
		return nil, err
	}
	cs.s.mu.RLock()
	defer cs.s.mu.RUnlock()
	csr, ok := cs.s.csrs[name]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cloneBytes(csr), nil
}

func (cs *CSRStorage) DeleteCSR(name string) error {
	if err := storage.ValidateEntityName(name); err != nil {
		return err
	}
	cs.s.mu.Lock()
	defer cs.s.mu.Unlock()
	if _, ok := cs.s.csrs[name]; !ok {
		return storage.ErrNotFound
	}
	delete(cs.s.csrs, name)
	return nil
}

func (cs *CSRStorage) ListCSRs() ([]string, error) {
	cs.s.mu.RLock()
	defer cs.s.mu.RUnlock()
	names := make([]string, 0, len(cs.s.csrs))
	for name := range cs.s.csrs {
		names = append(names, name)
	}
	return names, nil
}

// --- IndexDB ---

// IndexDB implements storage.IndexDB in memory.
type IndexDB struct{ s *store }

func (db *IndexDB) Empty() (bool, error) {
	db.s.mu.RLock()
	defer db.s.mu.RUnlock()
	return db.s.empty(), nil
}
func (db *IndexDB) Owned() (bool, error) { return true, nil }

func (db *IndexDB) Record(entry storage.IndexEntry) error {
	cloned, err := cloneIndexEntryChecked(entry)
	if err != nil {
		return fmt.Errorf("storage/memory: clone index entry: %w", err)
	}
	db.s.mu.Lock()
	defer db.s.mu.Unlock()
	db.s.entries = append(db.s.entries, cloned)
	return nil
}

func (db *IndexDB) Update(serial *big.Int, status storage.CertStatus, revokedAt time.Time, reason cert.RevocationReason) error {
	db.s.mu.Lock()
	defer db.s.mu.Unlock()
	for i, e := range db.s.entries {
		if e.Serial.Cmp(serial) == 0 {
			db.s.entries[i].Status = status
			if status == storage.StatusRevoked {
				db.s.entries[i].RevokedAt = revokedAt
				db.s.entries[i].RevocationReason = reason
			}
			return nil
		}
	}
	return storage.ErrNotFound
}

func (db *IndexDB) RecordAndUpdate(newEntry storage.IndexEntry, oldSerial *big.Int, status storage.CertStatus, revokedAt time.Time, reason cert.RevocationReason) error {
	cloned, err := cloneIndexEntryChecked(newEntry)
	if err != nil {
		return fmt.Errorf("storage/memory: clone index entry: %w", err)
	}
	db.s.mu.Lock()
	defer db.s.mu.Unlock()
	db.s.entries = append(db.s.entries, cloned)
	for i, e := range db.s.entries {
		if e.Serial.Cmp(oldSerial) == 0 {
			db.s.entries[i].Status = status
			if status == storage.StatusRevoked {
				db.s.entries[i].RevokedAt = revokedAt
				db.s.entries[i].RevocationReason = reason
			}
			break
		}
	}
	// If oldSerial is not in the index (e.g. cert was created by an external
	// tool), we still commit the new entry; the old one simply remains untracked.
	return nil
}

func (db *IndexDB) Query(filter storage.IndexFilter) ([]storage.IndexEntry, error) {
	db.s.mu.RLock()
	defer db.s.mu.RUnlock()
	var result []storage.IndexEntry
	for _, e := range db.s.entries {
		if filter.Status != nil && e.Status != *filter.Status {
			continue
		}
		if filter.Name != "" && e.Subject.CommonName != filter.Name {
			continue
		}
		result = append(result, cloneIndexEntry(e))
	}
	return result, nil
}

// --- SerialProvider ---

// SerialProvider implements storage.SerialProvider in memory.
type SerialProvider struct{ s *store }

func (sp *SerialProvider) Empty() (bool, error) {
	sp.s.mu.RLock()
	defer sp.s.mu.RUnlock()
	return sp.s.empty(), nil
}
func (sp *SerialProvider) Owned() (bool, error) { return true, nil }

func (sp *SerialProvider) Next() (*big.Int, error) {
	sp.s.mu.Lock()
	defer sp.s.mu.Unlock()
	n := new(big.Int).Set(sp.s.serial)
	sp.s.serial.Add(sp.s.serial, big.NewInt(1))
	return n, nil
}

// --- CRLHolder ---

// CRLHolder implements storage.CRLHolder in memory.
type CRLHolder struct{ s *store }

func (ch *CRLHolder) Empty() (bool, error) {
	ch.s.mu.RLock()
	defer ch.s.mu.RUnlock()
	return ch.s.empty(), nil
}
func (ch *CRLHolder) Owned() (bool, error) { return true, nil }

func (ch *CRLHolder) Put(pemBytes []byte) error {
	ch.s.mu.Lock()
	defer ch.s.mu.Unlock()
	ch.s.crlPEM = cloneBytes(pemBytes)
	return nil
}

func (ch *CRLHolder) Get() (*x509.RevocationList, error) {
	ch.s.mu.RLock()
	defer ch.s.mu.RUnlock()
	if ch.s.crlPEM == nil {
		return &x509.RevocationList{}, nil
	}
	block, _ := pem.Decode(ch.s.crlPEM)
	if block == nil {
		return &x509.RevocationList{}, nil
	}
	return x509.ParseRevocationList(block.Bytes)
}

// hexSerial is a package-local alias for storage.HexSerial.
func hexSerial(n *big.Int) string { return storage.HexSerial(n) }

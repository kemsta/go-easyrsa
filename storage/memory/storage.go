// Package memory provides in-memory implementations of all storage interfaces.
// Intended for unit testing — no persistence across process restarts.
package memory

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sync"
	"time"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// store holds all shared in-memory state.
type store struct {
	mu       sync.RWMutex
	pairs    map[string][]*cert.Pair // name → ordered list (latest last)
	bySerial map[string]*cert.Pair   // uppercase hex serial → pair
	csrs     map[string][]byte       // name → CSR PEM
	entries  []storage.IndexEntry    // index DB rows
	crlPEM   []byte                  // CRL PEM, nil if none
	serial   *big.Int                // next serial counter
}

func newStore() *store {
	return &store{
		pairs:    make(map[string][]*cert.Pair),
		bySerial: make(map[string]*cert.Pair),
		csrs:     make(map[string][]byte),
		serial:   big.NewInt(1),
	}
}

func (s *store) empty() bool {
	return len(s.pairs) == 0 && len(s.bySerial) == 0 && len(s.csrs) == 0 && len(s.entries) == 0 && len(s.crlPEM) == 0 && s.serial != nil && s.serial.Cmp(big.NewInt(1)) == 0
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
	ks.s.mu.Lock()
	defer ks.s.mu.Unlock()
	if pair.CertPEM != nil {
		// Upsert: remove all existing pairs for this name and clean up bySerial.
		for _, p := range ks.s.pairs[pair.Name] {
			if p.CertPEM != nil {
				if serial, err := p.Serial(); err == nil {
					delete(ks.s.bySerial, hexSerial(serial))
				}
			}
		}
		ks.s.pairs[pair.Name] = nil
		if serial, err := pair.Serial(); err == nil {
			ks.s.bySerial[hexSerial(serial)] = pair
		}
		ks.s.pairs[pair.Name] = append(ks.s.pairs[pair.Name], pair)
	} else {
		// Key-only put (GenReq): update the key in the most recent existing pair
		// rather than appending, so GetLastByName continues to return the cert.
		existing := ks.s.pairs[pair.Name]
		if len(existing) > 0 {
			existing[len(existing)-1].KeyPEM = pair.KeyPEM
		} else {
			ks.s.pairs[pair.Name] = append(ks.s.pairs[pair.Name], pair)
		}
	}
	return nil
}

func (ks *KeyStorage) GetByName(name string) ([]*cert.Pair, error) {
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()
	pairs := ks.s.pairs[name]
	if len(pairs) == 0 {
		return nil, storage.ErrNotFound
	}
	result := make([]*cert.Pair, len(pairs))
	for i, p := range pairs {
		cp := *p
		result[i] = &cp
	}
	return result, nil
}

func (ks *KeyStorage) GetLastByName(name string) (*cert.Pair, error) {
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()
	pairs := ks.s.pairs[name]
	if len(pairs) == 0 {
		return nil, storage.ErrNotFound
	}
	cp := *pairs[len(pairs)-1]
	return &cp, nil
}

func (ks *KeyStorage) GetBySerial(serial *big.Int) (*cert.Pair, error) {
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()
	pair, ok := ks.s.bySerial[hexSerial(serial)]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := *pair
	return &cp, nil
}

func (ks *KeyStorage) DeleteByName(name string) error {
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
	return nil
}

func (ks *KeyStorage) DeleteBySerial(serial *big.Int) error {
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
		for _, p := range pairs {
			pCopy := *p
			result = append(result, &pCopy)
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
	cs.s.mu.Lock()
	defer cs.s.mu.Unlock()
	cs.s.csrs[name] = csrPEM
	return nil
}

func (cs *CSRStorage) GetCSR(name string) ([]byte, error) {
	cs.s.mu.RLock()
	defer cs.s.mu.RUnlock()
	csr, ok := cs.s.csrs[name]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return csr, nil
}

func (cs *CSRStorage) DeleteCSR(name string) error {
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
	db.s.mu.Lock()
	defer db.s.mu.Unlock()
	if entry.Serial != nil {
		entry.Serial = new(big.Int).Set(entry.Serial)
	}
	db.s.entries = append(db.s.entries, entry)
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
	db.s.mu.Lock()
	defer db.s.mu.Unlock()
	if newEntry.Serial != nil {
		newEntry.Serial = new(big.Int).Set(newEntry.Serial)
	}
	db.s.entries = append(db.s.entries, newEntry)
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
		if e.Serial != nil {
			e.Serial = new(big.Int).Set(e.Serial)
		}
		result = append(result, e)
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
	ch.s.crlPEM = pemBytes
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

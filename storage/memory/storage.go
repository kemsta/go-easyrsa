// Package memory provides in-memory implementations of all storage interfaces.
// Intended for unit testing — no persistence across process restarts.
package memory

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sync"
	"time"

	"github.com/kemsta/go-easyrsa/cert"
	"github.com/kemsta/go-easyrsa/storage"
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

// New creates all five storage implementations sharing the same in-memory state.
func New() (*KeyStorage, *CSRStorage, *IndexDB, *SerialProvider, *CRLHolder) {
	s := newStore()
	return &KeyStorage{s}, &CSRStorage{s}, &IndexDB{s}, &SerialProvider{s}, &CRLHolder{s}
}

// --- KeyStorage ---

// KeyStorage implements storage.KeyStorage in memory.
type KeyStorage struct{ s *store }

func (ks *KeyStorage) Put(pair *cert.Pair) error {
	ks.s.mu.Lock()
	defer ks.s.mu.Unlock()
	ks.s.pairs[pair.Name] = append(ks.s.pairs[pair.Name], pair)
	if pair.CertPEM != nil {
		if serial, err := pair.Serial(); err == nil {
			ks.s.bySerial[hexSerial(serial)] = pair
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
	copy(result, pairs)
	return result, nil
}

func (ks *KeyStorage) GetLastByName(name string) (*cert.Pair, error) {
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()
	pairs := ks.s.pairs[name]
	if len(pairs) == 0 {
		return nil, storage.ErrNotFound
	}
	return pairs[len(pairs)-1], nil
}

func (ks *KeyStorage) GetBySerial(serial *big.Int) (*cert.Pair, error) {
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()
	pair, ok := ks.s.bySerial[hexSerial(serial)]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return pair, nil
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

func (db *IndexDB) Record(entry storage.IndexEntry) error {
	db.s.mu.Lock()
	defer db.s.mu.Unlock()
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
		result = append(result, e)
	}
	return result, nil
}

// --- SerialProvider ---

// SerialProvider implements storage.SerialProvider in memory.
type SerialProvider struct{ s *store }

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

// hexSerial returns the serial as uppercase even-length hex (e.g. 1 → "01").
func hexSerial(n *big.Int) string {
	h := n.Text(16)
	if len(h)%2 != 0 {
		h = "0" + h
	}
	// uppercase
	result := make([]byte, len(h))
	for i, c := range h {
		if c >= 'a' && c <= 'f' {
			result[i] = byte(c - 32)
		} else {
			result[i] = byte(c)
		}
	}
	return string(result)
}

// Package legacy provides read-only storage adapters for the v1 filesystem layout.
//
// Layout:
//
//	pkiDir/<name>/<serial>.crt
//	pkiDir/<name>/<serial>.key
//
// plus optional root-level files like crl.pem and serial.
package legacy

import (
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kemsta/go-easyrsa/cert"
	"github.com/kemsta/go-easyrsa/storage"
	fsstore "github.com/kemsta/go-easyrsa/storage/fs"
)

// KeyStorage implements storage.KeyStorage for the legacy v1 filesystem layout.
// All mutating methods return storage.ErrReadOnly.
type KeyStorage struct {
	pkiDir string
	caName string
	mu     sync.RWMutex
}

// NewKeyStorage creates a read-only legacy KeyStorage rooted at pkiDir.
func NewKeyStorage(pkiDir, caName string) *KeyStorage {
	if caName == "" {
		caName = "ca"
	}
	return &KeyStorage{pkiDir: pkiDir, caName: caName}
}

func (ks *KeyStorage) Empty() (bool, error) { return OwnershipProbe{Dir: ks.pkiDir}.Empty() }
func (ks *KeyStorage) Owned() (bool, error) { return OwnershipProbe{Dir: ks.pkiDir}.Owned() }
func (ks *KeyStorage) ReadOnly() bool       { return true }

func (ks *KeyStorage) Put(_ *cert.Pair) error          { return storage.ErrReadOnly }
func (ks *KeyStorage) DeleteByName(_ string) error     { return storage.ErrReadOnly }
func (ks *KeyStorage) DeleteBySerial(_ *big.Int) error { return storage.ErrReadOnly }

func (ks *KeyStorage) GetByName(name string) ([]*cert.Pair, error) {
	if !safeEntityName(name) {
		return nil, storage.ErrNotFound
	}
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	pairs, err := ks.scanName(name)
	if err != nil {
		return nil, err
	}
	if len(pairs) == 0 {
		return nil, storage.ErrNotFound
	}
	return pairs, nil
}

func (ks *KeyStorage) GetLastByName(name string) (*cert.Pair, error) {
	pairs, err := ks.GetByName(name)
	if err != nil {
		return nil, err
	}
	return clonePair(pairs[len(pairs)-1]), nil
}

func (ks *KeyStorage) GetBySerial(serial *big.Int) (*cert.Pair, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	pairs, err := ks.scanAll()
	if err != nil {
		return nil, err
	}
	for _, pair := range pairs {
		s, err := pair.Serial()
		if err != nil {
			continue
		}
		if s.Cmp(serial) == 0 {
			return clonePair(pair), nil
		}
	}
	return nil, storage.ErrNotFound
}

func (ks *KeyStorage) GetAll() ([]*cert.Pair, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	pairs, err := ks.scanAll()
	if err != nil {
		return nil, err
	}
	return pairs, nil
}

func (ks *KeyStorage) scanAll() ([]*cert.Pair, error) {
	entries, err := os.ReadDir(ks.pkiDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var all []*cert.Pair
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !safeEntityName(name) {
			continue
		}
		pairs, err := ks.scanName(name)
		if err != nil {
			return nil, err
		}
		all = append(all, pairs...)
	}

	sortPairs(all)
	return clonePairs(all), nil
}

func (ks *KeyStorage) scanName(name string) ([]*cert.Pair, error) {
	dir := filepath.Join(ks.pkiDir, name)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}

	var pairs []*cert.Pair
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		serialHex := strings.TrimSuffix(entry.Name(), ".crt")
		if _, ok := new(big.Int).SetString(serialHex, 16); !ok {
			continue
		}

		certPEM, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		pair := &cert.Pair{Name: name, CertPEM: certPEM}

		keyPath := filepath.Join(dir, serialHex+".key")
		if keyPEM, err := os.ReadFile(keyPath); err == nil {
			pair.KeyPEM = keyPEM
		} else if !os.IsNotExist(err) {
			return nil, err
		}

		pairs = append(pairs, pair)
	}

	sortPairs(pairs)
	return clonePairs(pairs), nil
}

func sortPairs(pairs []*cert.Pair) {
	sort.Slice(pairs, func(i, j int) bool {
		si, errI := pairs[i].Serial()
		sj, errJ := pairs[j].Serial()
		switch {
		case errI != nil && errJ != nil:
			return pairs[i].Name < pairs[j].Name
		case errI != nil:
			return true
		case errJ != nil:
			return false
		}
		if cmp := si.Cmp(sj); cmp != 0 {
			return cmp < 0
		}
		return pairs[i].Name < pairs[j].Name
	})
}

func clonePair(pair *cert.Pair) *cert.Pair {
	if pair == nil {
		return nil
	}
	cp := &cert.Pair{Name: pair.Name}
	if pair.CertPEM != nil {
		cp.CertPEM = append([]byte(nil), pair.CertPEM...)
	}
	if pair.KeyPEM != nil {
		cp.KeyPEM = append([]byte(nil), pair.KeyPEM...)
	}
	return cp
}

func clonePairs(pairs []*cert.Pair) []*cert.Pair {
	out := make([]*cert.Pair, len(pairs))
	for i, pair := range pairs {
		out[i] = clonePair(pair)
	}
	return out
}

func safeEntityName(name string) bool {
	if name == "" || name == "." || strings.Contains(name, "..") || strings.ContainsRune(name, 0) {
		return false
	}
	return !strings.ContainsAny(name, `/\\`)
}

// IndexDB implements a synthetic read-only certificate database for legacy PKIs.
// Query derives entries from legacy certs and crl.pem; mutating methods return
// storage.ErrReadOnly.
type IndexDB struct {
	storage *KeyStorage
	crl     storage.CRLHolder
}

// NewIndexDB creates a synthetic read-only IndexDB over legacy storage.
func NewIndexDB(ks *KeyStorage, crl storage.CRLHolder) *IndexDB {
	return &IndexDB{storage: ks, crl: crl}
}

func (db *IndexDB) Empty() (bool, error) { return db.storage.Empty() }
func (db *IndexDB) Owned() (bool, error) { return db.storage.Owned() }
func (db *IndexDB) ReadOnly() bool       { return true }

func (db *IndexDB) Record(_ storage.IndexEntry) error { return storage.ErrReadOnly }

func (db *IndexDB) Update(_ *big.Int, _ storage.CertStatus, _ time.Time, _ cert.RevocationReason) error {
	return storage.ErrReadOnly
}

func (db *IndexDB) RecordAndUpdate(_ storage.IndexEntry, _ *big.Int, _ storage.CertStatus, _ time.Time, _ cert.RevocationReason) error {
	return storage.ErrReadOnly
}

func (db *IndexDB) Query(filter storage.IndexFilter) ([]storage.IndexEntry, error) {
	pairs, err := db.storage.GetAll()
	if err != nil {
		return nil, err
	}
	revoked, err := db.revokedMap()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var out []storage.IndexEntry
	for _, pair := range pairs {
		crt, err := pair.Certificate()
		if err != nil {
			continue
		}
		entry := storage.IndexEntry{
			Status:    storage.StatusValid,
			ExpiresAt: crt.NotAfter,
			Serial:    new(big.Int).Set(crt.SerialNumber),
			Subject:   crt.Subject,
		}
		if r, ok := revoked[storage.HexSerial(crt.SerialNumber)]; ok {
			entry.Status = storage.StatusRevoked
			entry.RevokedAt = r.at
			entry.RevocationReason = r.reason
		} else if crt.NotAfter.Before(now) {
			entry.Status = storage.StatusExpired
		}
		if filter.Status != nil && entry.Status != *filter.Status {
			continue
		}
		if filter.Name != "" && entry.Subject.CommonName != filter.Name {
			continue
		}
		out = append(out, entry)
	}

	sort.Slice(out, func(i, j int) bool {
		if cmp := out[i].Serial.Cmp(out[j].Serial); cmp != 0 {
			return cmp < 0
		}
		return out[i].Subject.CommonName < out[j].Subject.CommonName
	})
	return out, nil
}

type revokedMeta struct {
	at     time.Time
	reason cert.RevocationReason
}

func (db *IndexDB) revokedMap() (map[string]revokedMeta, error) {
	crl, err := db.crl.Get()
	if err != nil {
		return nil, err
	}
	out := make(map[string]revokedMeta, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		reason := cert.ReasonUnspecified
		if entry.ReasonCode >= 0 {
			reason = cert.RevocationReason(entry.ReasonCode)
		}
		out[storage.HexSerial(entry.SerialNumber)] = revokedMeta{
			at:     entry.RevocationTime,
			reason: reason,
		}
	}
	return out, nil
}

// CSRStorage is a read-only placeholder for legacy PKIs, which have no CSR store.
type CSRStorage struct{ pkiDir string }

// NewCSRStorage creates a read-only CSRStorage stub.
func NewCSRStorage(pkiDir string) *CSRStorage { return &CSRStorage{pkiDir: pkiDir} }

func (cs *CSRStorage) Empty() (bool, error) { return OwnershipProbe{Dir: cs.pkiDir}.Empty() }
func (cs *CSRStorage) Owned() (bool, error) { return OwnershipProbe{Dir: cs.pkiDir}.Owned() }
func (cs *CSRStorage) ReadOnly() bool       { return true }

func (cs *CSRStorage) PutCSR(_ string, _ []byte) error { return storage.ErrReadOnly }
func (cs *CSRStorage) GetCSR(_ string) ([]byte, error) { return nil, storage.ErrReadOnly }
func (cs *CSRStorage) DeleteCSR(_ string) error        { return storage.ErrReadOnly }
func (cs *CSRStorage) ListCSRs() ([]string, error)     { return nil, storage.ErrReadOnly }

// SerialProvider is a read-only placeholder for legacy PKIs.
type SerialProvider struct{ pkiDir string }

// NewSerialProvider creates a read-only SerialProvider stub.
func NewSerialProvider(pkiDir string) *SerialProvider { return &SerialProvider{pkiDir: pkiDir} }

func (sp *SerialProvider) Empty() (bool, error) { return OwnershipProbe{Dir: sp.pkiDir}.Empty() }
func (sp *SerialProvider) Owned() (bool, error) { return OwnershipProbe{Dir: sp.pkiDir}.Owned() }
func (sp *SerialProvider) ReadOnly() bool       { return true }
func (sp *SerialProvider) Next() (*big.Int, error) {
	return nil, storage.ErrReadOnly
}

// CRLHolder provides read-only access to pkiDir/crl.pem.
type CRLHolder struct {
	pkiDir string
	reader storage.CRLHolder
}

// NewCRLHolder creates a read-only CRLHolder backed by pkiDir/crl.pem.
func NewCRLHolder(pkiDir string) *CRLHolder {
	return &CRLHolder{pkiDir: pkiDir, reader: fsstore.NewCRLHolder(pkiDir)}
}

func (ch *CRLHolder) Empty() (bool, error) { return OwnershipProbe{Dir: ch.pkiDir}.Empty() }
func (ch *CRLHolder) Owned() (bool, error) { return OwnershipProbe{Dir: ch.pkiDir}.Owned() }
func (ch *CRLHolder) ReadOnly() bool       { return true }
func (ch *CRLHolder) Put(_ []byte) error {
	return storage.ErrReadOnly
}

func (ch *CRLHolder) Get() (*x509.RevocationList, error) {
	return ch.reader.Get()
}

var (
	_ storage.KeyStorage         = (*KeyStorage)(nil)
	_ storage.IndexDB            = (*IndexDB)(nil)
	_ storage.CSRStorage         = (*CSRStorage)(nil)
	_ storage.SerialProvider     = (*SerialProvider)(nil)
	_ storage.CRLHolder          = (*CRLHolder)(nil)
	_ storage.ReadOnly           = (*KeyStorage)(nil)
	_ storage.ReadOnly           = (*IndexDB)(nil)
	_ storage.ReadOnly           = (*CSRStorage)(nil)
	_ storage.ReadOnly           = (*SerialProvider)(nil)
	_ storage.ReadOnly           = (*CRLHolder)(nil)
	_ storage.OwnershipValidator = (*KeyStorage)(nil)
	_ storage.OwnershipValidator = (*IndexDB)(nil)
	_ storage.OwnershipValidator = (*CSRStorage)(nil)
	_ storage.OwnershipValidator = (*SerialProvider)(nil)
	_ storage.OwnershipValidator = (*CRLHolder)(nil)
)

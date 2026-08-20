package memory

import (
	"math/big"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// LifecycleStorage tracks Easy-RSA lifecycle locations in memory.
type LifecycleStorage struct{ s *store }

func (l *LifecycleStorage) MoveIssuedToExpired(name string) error {
	if err := storage.ValidateEntityName(name); err != nil {
		return err
	}
	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	if _, exists := l.s.expired[name]; exists {
		return storage.ErrConflict
	}
	pair, err := l.issuedPair(name)
	if err != nil {
		return err
	}
	l.s.expired[name] = cloneBytes(pair.CertPEM)
	l.s.unavailable[name] = true
	return nil
}

func (l *LifecycleStorage) MoveIssuedToRenewed(name string) error {
	if err := storage.ValidateEntityName(name); err != nil {
		return err
	}
	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	if _, exists := l.s.renewed[name]; exists {
		return storage.ErrConflict
	}
	pair, err := l.issuedPair(name)
	if err != nil {
		return err
	}
	l.s.renewed[name] = cloneBytes(pair.CertPEM)
	l.s.unavailable[name] = true
	return nil
}

func (l *LifecycleStorage) MoveIssuedToRevoked(name string, serial *big.Int) error {
	if err := storage.ValidateEntityName(name); err != nil {
		return err
	}
	if err := storage.ValidateSerial(serial); err != nil {
		return err
	}
	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	key := hexSerial(serial)
	if _, exists := l.s.revokedCerts[key]; exists {
		return storage.ErrConflict
	}
	pair, err := l.issuedPair(name)
	if err != nil {
		return err
	}
	l.s.revokedCerts[key] = cloneBytes(pair.CertPEM)
	l.s.revokedNames[key] = name
	if pair.KeyPEM != nil {
		l.s.revokedKeys[key] = cloneBytes(pair.KeyPEM)
		pair.KeyPEM = nil
	}
	if csr, ok := l.s.csrs[name]; ok {
		l.s.revokedCSRs[key] = cloneBytes(csr)
		delete(l.s.csrs, name)
	}
	l.s.unavailable[name] = true
	return nil
}

func (l *LifecycleStorage) MoveExpiredToRevoked(name string, serial *big.Int) error {
	if err := storage.ValidateEntityName(name); err != nil {
		return err
	}
	if err := storage.ValidateSerial(serial); err != nil {
		return err
	}
	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	key := hexSerial(serial)
	if _, exists := l.s.revokedCerts[key]; exists {
		return storage.ErrConflict
	}
	certificate, ok := l.s.expired[name]
	if !ok {
		return storage.ErrNotFound
	}
	l.s.revokedCerts[key] = cloneBytes(certificate)
	l.s.revokedNames[key] = name
	delete(l.s.expired, name)
	return nil
}

func (l *LifecycleStorage) MoveRenewedToRevoked(name string, serial *big.Int) error {
	if err := storage.ValidateEntityName(name); err != nil {
		return err
	}
	if err := storage.ValidateSerial(serial); err != nil {
		return err
	}
	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	key := hexSerial(serial)
	if _, exists := l.s.revokedCerts[key]; exists {
		return storage.ErrConflict
	}
	certificate, ok := l.s.renewed[name]
	if !ok {
		return storage.ErrNotFound
	}
	l.s.revokedCerts[key] = cloneBytes(certificate)
	l.s.revokedNames[key] = name
	delete(l.s.renewed, name)
	return nil
}

func (l *LifecycleStorage) GetRenewedCertificate(name string) ([]byte, error) {
	if err := storage.ValidateEntityName(name); err != nil {
		return nil, err
	}
	l.s.mu.RLock()
	defer l.s.mu.RUnlock()
	certificate, ok := l.s.renewed[name]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cloneBytes(certificate), nil
}

func (l *LifecycleStorage) issuedPair(name string) (*cert.Pair, error) {
	if l.s.unavailable[name] {
		return nil, storage.ErrNotFound
	}
	pairs := l.s.pairs[name]
	for i := len(pairs) - 1; i >= 0; i-- {
		if pairs[i].CertPEM != nil {
			return pairs[i], nil
		}
	}
	return nil, storage.ErrNotFound
}

var _ storage.LifecycleStorage = (*LifecycleStorage)(nil)

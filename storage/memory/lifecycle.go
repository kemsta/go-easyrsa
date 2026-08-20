package memory

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// LifecycleStorage tracks Easy-RSA lifecycle locations in memory.
type LifecycleStorage struct{ s *store }

func (l *LifecycleStorage) MoveIssuedToExpired(name string, serial *big.Int) error {
	if err := storage.ValidateEntityName(name); err != nil {
		return err
	}
	if err := storage.ValidateSerial(serial); err != nil {
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

func (l *LifecycleStorage) MoveIssuedToRenewed(name string, serial *big.Int) error {
	if err := storage.ValidateEntityName(name); err != nil {
		return err
	}
	if err := storage.ValidateSerial(serial); err != nil {
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
	l.s.revokedAssetsArchived[key] = true
	if pair.KeyPEM != nil {
		l.s.revokedKeys[key] = cloneBytes(pair.KeyPEM)
		pair.KeyPEM = nil
	}
	delete(l.s.pendingKeys, name)
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
	l.s.revokedAssetsArchived[key] = false
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
	l.s.revokedAssetsArchived[key] = false
	delete(l.s.renewed, name)
	return nil
}

func (l *LifecycleStorage) GetExpiredCertificate(name string) ([]byte, error) {
	if err := storage.ValidateEntityName(name); err != nil {
		return nil, err
	}
	l.s.mu.RLock()
	defer l.s.mu.RUnlock()
	certificate, ok := l.s.expired[name]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cloneBytes(certificate), nil
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

func (l *LifecycleStorage) ExportState() (storage.LifecycleState, error) {
	l.s.mu.RLock()
	defer l.s.mu.RUnlock()
	var state storage.LifecycleState
	for name, certificate := range l.s.expired {
		key, request := l.currentAssets(name)
		record, err := lifecycleRecord(name, certificate, key, request)
		if err != nil {
			return storage.LifecycleState{}, err
		}
		state.Expired = append(state.Expired, record)
	}
	for name, certificate := range l.s.renewed {
		key, request := l.currentAssets(name)
		record, err := lifecycleRecord(name, certificate, key, request)
		if err != nil {
			return storage.LifecycleState{}, err
		}
		state.Renewed = append(state.Renewed, record)
	}
	for serialHex, certificate := range l.s.revokedCerts {
		serial := new(big.Int)
		if _, ok := serial.SetString(serialHex, 16); !ok {
			return storage.LifecycleState{}, fmt.Errorf("storage/memory: invalid revoked serial %q", serialHex)
		}
		archived := l.s.revokedAssetsArchived[serialHex]
		key, request := l.s.revokedKeys[serialHex], l.s.revokedCSRs[serialHex]
		if !archived {
			key, request = l.currentAssets(l.s.revokedNames[serialHex])
		}
		record := storage.LifecycleRecord{
			Name:           l.s.revokedNames[serialHex],
			Serial:         serial,
			CertificatePEM: cloneBytes(certificate),
			PrivateKeyPEM:  cloneBytes(key),
			CSRPEM:         cloneBytes(request),
			AssetsArchived: archived,
		}
		state.Revoked = append(state.Revoked, record)
	}
	sortLifecycleRecords(state.Expired)
	sortLifecycleRecords(state.Renewed)
	sortLifecycleRecords(state.Revoked)
	return state, nil
}

func (l *LifecycleStorage) currentAssets(name string) ([]byte, []byte) {
	var key []byte
	if pending := l.s.pendingKeys[name]; len(pending) > 0 {
		key = pending
	} else {
		pairs := l.s.pairs[name]
		if len(pairs) > 0 {
			key = pairs[len(pairs)-1].KeyPEM
		}
	}
	return cloneBytes(key), cloneBytes(l.s.csrs[name])
}

func (l *LifecycleStorage) ReplaceState(state storage.LifecycleState) error {
	expired := make(map[string][]byte)
	renewed := make(map[string][]byte)
	revokedCerts := make(map[string][]byte)
	revokedKeys := make(map[string][]byte)
	revokedCSRs := make(map[string][]byte)
	revokedNames := make(map[string]string)
	revokedAssetsArchived := make(map[string]bool)
	for _, record := range state.Expired {
		if record.AssetsArchived {
			return fmt.Errorf("storage/memory: archived assets are only valid for revoked certificates")
		}
		if err := validateLifecycleRecord(record); err != nil {
			return err
		}
		if _, exists := expired[record.Name]; exists {
			return storage.ErrConflict
		}
		expired[record.Name] = cloneBytes(record.CertificatePEM)
	}
	for _, record := range state.Renewed {
		if record.AssetsArchived {
			return fmt.Errorf("storage/memory: archived assets are only valid for revoked certificates")
		}
		if err := validateLifecycleRecord(record); err != nil {
			return err
		}
		if _, exists := renewed[record.Name]; exists {
			return storage.ErrConflict
		}
		renewed[record.Name] = cloneBytes(record.CertificatePEM)
	}
	for _, record := range state.Revoked {
		if err := validateLifecycleRecord(record); err != nil {
			return err
		}
		serialHex := hexSerial(record.Serial)
		if _, exists := revokedCerts[serialHex]; exists {
			return storage.ErrConflict
		}
		revokedCerts[serialHex] = cloneBytes(record.CertificatePEM)
		if record.AssetsArchived {
			revokedKeys[serialHex] = cloneBytes(record.PrivateKeyPEM)
			revokedCSRs[serialHex] = cloneBytes(record.CSRPEM)
		}
		revokedNames[serialHex] = record.Name
		revokedAssetsArchived[serialHex] = record.AssetsArchived
	}

	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	l.s.expired = expired
	l.s.renewed = renewed
	l.s.revokedCerts = revokedCerts
	l.s.revokedKeys = revokedKeys
	l.s.revokedCSRs = revokedCSRs
	l.s.revokedNames = revokedNames
	l.s.revokedAssetsArchived = revokedAssetsArchived
	l.s.unavailable = make(map[string]bool)
	preservedAssets := append(append(append([]storage.LifecycleRecord(nil), state.Expired...), state.Renewed...), state.Revoked...)
	for _, record := range preservedAssets {
		if record.AssetsArchived {
			continue
		}
		pairs := l.s.pairs[record.Name]
		if len(pairs) > 0 && len(record.PrivateKeyPEM) > 0 {
			pairs[len(pairs)-1].KeyPEM = cloneBytes(record.PrivateKeyPEM)
		}
		if len(record.CSRPEM) > 0 {
			l.s.csrs[record.Name] = cloneBytes(record.CSRPEM)
		}
	}
	for _, record := range append(append([]storage.LifecycleRecord(nil), state.Expired...), state.Revoked...) {
		pairs := l.s.pairs[record.Name]
		if len(pairs) == 0 {
			continue
		}
		currentSerial, err := pairs[len(pairs)-1].Serial()
		if err != nil || currentSerial.Cmp(record.Serial) != 0 {
			continue
		}
		l.s.unavailable[record.Name] = true
		if _, revoked := revokedCerts[hexSerial(record.Serial)]; revoked && record.AssetsArchived {
			pairs[len(pairs)-1].KeyPEM = nil
			delete(l.s.pendingKeys, record.Name)
			delete(l.s.csrs, record.Name)
		}
	}
	return nil
}

func lifecycleRecord(name string, certificatePEM, keyPEM, csrPEM []byte) (storage.LifecycleRecord, error) {
	pair := &cert.Pair{Name: name, CertPEM: certificatePEM}
	serial, err := pair.Serial()
	if err != nil {
		return storage.LifecycleRecord{}, err
	}
	return storage.LifecycleRecord{
		Name:           name,
		Serial:         new(big.Int).Set(serial),
		CertificatePEM: cloneBytes(certificatePEM),
		PrivateKeyPEM:  cloneBytes(keyPEM),
		CSRPEM:         cloneBytes(csrPEM),
	}, nil
}

func validateLifecycleRecord(record storage.LifecycleRecord) error {
	if err := storage.ValidateEntityName(record.Name); err != nil {
		return err
	}
	if err := storage.ValidateSerial(record.Serial); err != nil {
		return err
	}
	parsed, err := (&cert.Pair{Name: record.Name, CertPEM: record.CertificatePEM}).Serial()
	if err != nil {
		return err
	}
	if parsed.Cmp(record.Serial) != 0 {
		return fmt.Errorf("storage/memory: lifecycle serial does not match certificate")
	}
	return nil
}

func sortLifecycleRecords(records []storage.LifecycleRecord) {
	sort.Slice(records, func(i, j int) bool {
		if comparison := records[i].Serial.Cmp(records[j].Serial); comparison != 0 {
			return comparison < 0
		}
		return records[i].Name < records[j].Name
	})
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

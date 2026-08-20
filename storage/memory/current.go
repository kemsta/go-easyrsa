package memory

import (
	"sort"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func (ks *KeyStorage) CurrentCertificates() ([]storage.CurrentCertificate, error) {
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()
	var current []storage.CurrentCertificate
	for name, pairs := range ks.s.pairs {
		if ks.s.unavailable[name] {
			continue
		}
		for i := len(pairs) - 1; i >= 0; i-- {
			if len(pairs[i].CertPEM) == 0 {
				continue
			}
			serial, err := pairs[i].Serial()
			if err != nil {
				return nil, err
			}
			current = append(current, storage.CurrentCertificate{
				Name:          name,
				Serial:        cloneBigInt(serial),
				PrivateKeyPEM: cloneBytes(pairs[i].KeyPEM),
			})
			break
		}
	}
	sort.Slice(current, func(i, j int) bool { return current[i].Name < current[j].Name })
	return current, nil
}

func (ks *KeyStorage) ReplaceCurrentCertificates(current []storage.CurrentCertificate) error {
	selected := make(map[string]*cert.Pair, len(current))
	serials := make(map[string]struct{}, len(current))
	ks.s.mu.Lock()
	defer ks.s.mu.Unlock()
	for _, record := range current {
		if err := storage.ValidateEntityName(record.Name); err != nil {
			return err
		}
		if err := storage.ValidateSerial(record.Serial); err != nil {
			return err
		}
		if _, exists := selected[record.Name]; exists {
			return storage.ErrConflict
		}
		serialKey := hexSerial(record.Serial)
		if _, exists := serials[serialKey]; exists {
			return storage.ErrConflict
		}
		pair, ok := ks.s.bySerial[serialKey]
		if !ok || pair.Name != record.Name {
			return storage.ErrNotFound
		}
		pair.KeyPEM = cloneBytes(record.PrivateKeyPEM)
		selected[record.Name] = pair
		serials[serialKey] = struct{}{}
	}

	ks.s.unavailable = make(map[string]bool)
	for name, pairs := range ks.s.pairs {
		hasCertificate := false
		for _, pair := range pairs {
			if len(pair.CertPEM) > 0 {
				hasCertificate = true
				break
			}
		}
		if hasCertificate {
			ks.s.unavailable[name] = true
		}
	}
	for name, selectedPair := range selected {
		pairs := ks.s.pairs[name]
		for i, pair := range pairs {
			if pair != selectedPair {
				continue
			}
			pairs = append(append(pairs[:i:i], pairs[i+1:]...), pair)
			ks.s.pairs[name] = pairs
			delete(ks.s.unavailable, name)
			break
		}
	}
	return nil
}

var _ storage.CurrentCertificateStore = (*KeyStorage)(nil)

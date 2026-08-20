package fs

import (
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

func (ks *KeyStorage) CurrentCertificates() ([]storage.CurrentCertificate, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	var current []storage.CurrentCertificate
	if certificatePEM, err := os.ReadFile(ks.certPath(ks.caName)); err == nil {
		serial, err := serialFromCertificatePEM(certificatePEM)
		if err != nil {
			return nil, err
		}
		record := storage.CurrentCertificate{Name: ks.caName, Serial: new(big.Int).Set(serial)}
		if key, err := os.ReadFile(ks.keyPath(ks.caName)); err == nil {
			record.PrivateKeyPEM = append([]byte(nil), key...)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		current = append(current, record)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(ks.pkiDir, "issued"))
	if errors.Is(err, fs.ErrNotExist) {
		return current, nil
	}
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".crt")
		if err := storage.ValidateEntityName(name); err != nil {
			return nil, err
		}
		certificatePEM, err := os.ReadFile(filepath.Join(ks.pkiDir, "issued", entry.Name()))
		if err != nil {
			return nil, err
		}
		serial, err := serialFromCertificatePEM(certificatePEM)
		if err != nil {
			return nil, err
		}
		record := storage.CurrentCertificate{Name: name, Serial: new(big.Int).Set(serial)}
		if key, err := os.ReadFile(ks.keyPath(name)); err == nil {
			record.PrivateKeyPEM = append([]byte(nil), key...)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		current = append(current, record)
	}
	sort.Slice(current, func(i, j int) bool { return current[i].Name < current[j].Name })
	return current, nil
}

func (ks *KeyStorage) ReplaceCurrentCertificates(current []storage.CurrentCertificate) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	certificates := make(map[string][]byte, len(current))
	serials := make(map[string]struct{}, len(current))
	for _, record := range current {
		if err := storage.ValidateEntityName(record.Name); err != nil {
			return err
		}
		if err := storage.ValidateSerial(record.Serial); err != nil {
			return err
		}
		if _, exists := certificates[record.Name]; exists {
			return storage.ErrConflict
		}
		serialKey := storage.HexSerial(record.Serial)
		if _, exists := serials[serialKey]; exists {
			return storage.ErrConflict
		}
		certificatePEM, err := os.ReadFile(ks.serialPath(record.Serial))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return storage.ErrNotFound
			}
			return err
		}
		parsedSerial, err := serialFromCertificatePEM(certificatePEM)
		if err != nil {
			return err
		}
		if parsedSerial.Cmp(record.Serial) != 0 {
			return storage.ErrConflict
		}
		certificates[record.Name] = certificatePEM
		serials[serialKey] = struct{}{}
	}

	if err := removeIfExists(ks.certPath(ks.caName)); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(ks.pkiDir, "issued"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".crt") {
			if err := os.Remove(filepath.Join(ks.pkiDir, "issued", entry.Name())); err != nil {
				return err
			}
		}
	}
	for _, record := range current {
		if err := writeFile(ks.certPath(record.Name), certificates[record.Name]); err != nil {
			return err
		}
		if err := writeFile(ks.nameSidecarPath(record.Serial), []byte(record.Name)); err != nil {
			return err
		}
		if len(record.PrivateKeyPEM) > 0 {
			if err := writeAtomicMode(ks.keyPath(record.Name), record.PrivateKeyPEM, 0o600); err != nil {
				return err
			}
		} else if err := removeIfExists(ks.keyPath(record.Name)); err != nil {
			return err
		}
	}
	return nil
}

var _ storage.CurrentCertificateStore = (*KeyStorage)(nil)

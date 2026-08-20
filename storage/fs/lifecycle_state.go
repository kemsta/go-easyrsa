package fs

import (
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func (l *LifecycleStorage) ExportState() (storage.LifecycleState, error) {
	expired, err := l.exportNamedDirectory("expired")
	if err != nil {
		return storage.LifecycleState{}, err
	}
	renewed, err := l.exportNamedDirectory(filepath.Join("renewed", "issued"))
	if err != nil {
		return storage.LifecycleState{}, err
	}
	revoked, err := l.exportRevoked()
	if err != nil {
		return storage.LifecycleState{}, err
	}
	return storage.LifecycleState{Expired: expired, Renewed: renewed, Revoked: revoked}, nil
}

func (l *LifecycleStorage) exportNamedDirectory(relativeDirectory string) ([]storage.LifecycleRecord, error) {
	directory := filepath.Join(l.pkiDir, relativeDirectory)
	entries, err := os.ReadDir(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []storage.LifecycleRecord
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".crt")
		if err := storage.ValidateEntityName(name); err != nil {
			return nil, err
		}
		certificatePEM, err := readLifecycleFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		serial, err := (&cert.Pair{Name: name, CertPEM: certificatePEM}).Serial()
		if err != nil {
			return nil, err
		}
		record := storage.LifecycleRecord{
			Name:           name,
			Serial:         new(big.Int).Set(serial),
			CertificatePEM: certificatePEM,
		}
		if key, err := readLifecycleFile(filepath.Join(l.pkiDir, "private", name+".key")); err == nil {
			record.PrivateKeyPEM = key
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		if request, err := readLifecycleFile(filepath.Join(l.pkiDir, "reqs", name+".req")); err == nil {
			record.CSRPEM = request
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		records = append(records, record)
	}
	sortLifecycleStateRecords(records)
	return records, nil
}

func (l *LifecycleStorage) exportRevoked() ([]storage.LifecycleRecord, error) {
	directory := filepath.Join(l.pkiDir, "revoked", "certs_by_serial")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []storage.LifecycleRecord
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		serialHex := strings.TrimSuffix(entry.Name(), ".crt")
		serial := new(big.Int)
		if _, ok := serial.SetString(serialHex, 16); !ok || serial.Sign() <= 0 {
			return nil, fmt.Errorf("storage/fs: invalid revoked serial %q", serialHex)
		}
		certificatePEM, err := readLifecycleFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		name, err := l.nameForSerial(serial, certificatePEM)
		if err != nil {
			return nil, err
		}
		_, markerErr := os.Stat(filepath.Join(l.pkiDir, "certs_by_serial", storage.HexSerial(serial)+".revoked-assets"))
		assetsArchived := markerErr == nil
		if markerErr != nil && !errors.Is(markerErr, fs.ErrNotExist) {
			return nil, markerErr
		}
		if !assetsArchived {
			for _, candidate := range []string{
				filepath.Join(l.pkiDir, "revoked", "private_by_serial", storage.HexSerial(serial)+".key"),
				filepath.Join(l.pkiDir, "revoked", "reqs_by_serial", storage.HexSerial(serial)+".req"),
			} {
				if _, err := os.Stat(candidate); err == nil {
					assetsArchived = true
					break
				} else if !errors.Is(err, fs.ErrNotExist) {
					return nil, err
				}
			}
		}
		record := storage.LifecycleRecord{
			Name:           name,
			Serial:         new(big.Int).Set(serial),
			CertificatePEM: certificatePEM,
			AssetsArchived: assetsArchived,
		}
		keyPath := filepath.Join(l.pkiDir, "private", name+".key")
		requestPath := filepath.Join(l.pkiDir, "reqs", name+".req")
		if assetsArchived {
			keyPath = filepath.Join(l.pkiDir, "revoked", "private_by_serial", storage.HexSerial(serial)+".key")
			requestPath = filepath.Join(l.pkiDir, "revoked", "reqs_by_serial", storage.HexSerial(serial)+".req")
		}
		if key, err := readLifecycleFile(keyPath); err == nil {
			record.PrivateKeyPEM = key
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		if request, err := readLifecycleFile(requestPath); err == nil {
			record.CSRPEM = request
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		records = append(records, record)
	}
	sortLifecycleStateRecords(records)
	return records, nil
}

func (l *LifecycleStorage) nameForSerial(serial *big.Int, certificatePEM []byte) (string, error) {
	if sidecar, err := os.ReadFile(filepath.Join(l.pkiDir, "certs_by_serial", storage.HexSerial(serial)+".name")); err == nil {
		if name := strings.TrimSpace(string(sidecar)); name != "" {
			if err := storage.ValidateEntityName(name); err != nil {
				return "", err
			}
			return name, nil
		}
	}
	certificate, err := (&cert.Pair{CertPEM: certificatePEM}).Certificate()
	if err != nil {
		return "", err
	}
	if err := storage.ValidateEntityName(certificate.Subject.CommonName); err != nil {
		return "", err
	}
	return certificate.Subject.CommonName, nil
}

func (l *LifecycleStorage) ReplaceState(state storage.LifecycleState) error {
	if err := validateLifecycleState(state); err != nil {
		return err
	}
	for _, relative := range []string{"expired", "renewed", "revoked"} {
		if err := os.RemoveAll(filepath.Join(l.pkiDir, relative)); err != nil {
			return err
		}
	}
	for _, record := range state.Expired {
		if err := l.writeLifecycleRecord(filepath.Join("expired", record.Name+".crt"), record, false); err != nil {
			return err
		}
		if err := l.restorePreservedAssets(record); err != nil {
			return err
		}
		if err := l.removeMatchingCurrent(record, false); err != nil {
			return err
		}
	}
	for _, record := range state.Renewed {
		if err := l.writeLifecycleRecord(filepath.Join("renewed", "issued", record.Name+".crt"), record, false); err != nil {
			return err
		}
		if err := l.restorePreservedAssets(record); err != nil {
			return err
		}
	}
	for _, record := range state.Revoked {
		hexSerial := storage.HexSerial(record.Serial)
		if err := l.writeLifecycleRecord(filepath.Join("revoked", "certs_by_serial", hexSerial+".crt"), record, true); err != nil {
			return err
		}
		if !record.AssetsArchived {
			if err := l.restorePreservedAssets(record); err != nil {
				return err
			}
		}
		if err := l.removeMatchingCurrent(record, record.AssetsArchived); err != nil {
			return err
		}
	}
	return nil
}

func (l *LifecycleStorage) writeLifecycleRecord(certificatePath string, record storage.LifecycleRecord, revoked bool) error {
	if err := writeAtomicMode(filepath.Join(l.pkiDir, certificatePath), record.CertificatePEM, 0o644); err != nil {
		return err
	}
	hexSerial := storage.HexSerial(record.Serial)
	if err := writeAtomicMode(filepath.Join(l.pkiDir, "certs_by_serial", hexSerial+".name"), []byte(record.Name), 0o600); err != nil {
		return err
	}
	if !revoked || !record.AssetsArchived {
		return nil
	}
	if err := writeAtomicMode(filepath.Join(l.pkiDir, "certs_by_serial", hexSerial+".revoked-assets"), []byte("issued"), 0o600); err != nil {
		return err
	}
	if len(record.PrivateKeyPEM) > 0 {
		if err := writeAtomicMode(filepath.Join(l.pkiDir, "revoked", "private_by_serial", hexSerial+".key"), record.PrivateKeyPEM, 0o600); err != nil {
			return err
		}
	}
	if len(record.CSRPEM) > 0 {
		if err := writeAtomicMode(filepath.Join(l.pkiDir, "revoked", "reqs_by_serial", hexSerial+".req"), record.CSRPEM, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (l *LifecycleStorage) restorePreservedAssets(record storage.LifecycleRecord) error {
	if len(record.PrivateKeyPEM) > 0 {
		if err := writeAtomicMode(filepath.Join(l.pkiDir, "private", record.Name+".key"), record.PrivateKeyPEM, 0o600); err != nil {
			return err
		}
	}
	if len(record.CSRPEM) > 0 {
		if err := writeAtomicMode(filepath.Join(l.pkiDir, "reqs", record.Name+".req"), record.CSRPEM, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (l *LifecycleStorage) removeMatchingCurrent(record storage.LifecycleRecord, removeKeyAndRequest bool) error {
	currentPath := filepath.Join(l.pkiDir, "issued", record.Name+".crt")
	currentPEM, err := os.ReadFile(currentPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	currentSerial, err := serialFromCertificatePEM(currentPEM)
	if err != nil || currentSerial.Cmp(record.Serial) != 0 {
		return err
	}
	if err := removeIfExists(currentPath); err != nil {
		return err
	}
	if removeKeyAndRequest {
		if err := removeIfExists(filepath.Join(l.pkiDir, "private", record.Name+".key")); err != nil {
			return err
		}
		if err := removeIfExists(filepath.Join(l.pkiDir, "reqs", record.Name+".req")); err != nil {
			return err
		}
	}
	return nil
}

func validateLifecycleState(state storage.LifecycleState) error {
	seenLocations := make(map[string]struct{})
	seenRevoked := make(map[string]struct{})
	for location, records := range map[string][]storage.LifecycleRecord{
		"expired": state.Expired,
		"renewed": state.Renewed,
		"revoked": state.Revoked,
	} {
		for _, record := range records {
			if location != "revoked" && record.AssetsArchived {
				return fmt.Errorf("storage/fs: archived assets are only valid for revoked certificates")
			}
			if err := storage.ValidateEntityName(record.Name); err != nil {
				return err
			}
			if err := storage.ValidateSerial(record.Serial); err != nil {
				return err
			}
			serial, err := (&cert.Pair{Name: record.Name, CertPEM: record.CertificatePEM}).Serial()
			if err != nil {
				return err
			}
			if serial.Cmp(record.Serial) != 0 {
				return fmt.Errorf("storage/fs: lifecycle serial does not match certificate")
			}
			key := location + "\x00" + record.Name
			if _, exists := seenLocations[key]; exists {
				return storage.ErrConflict
			}
			seenLocations[key] = struct{}{}
			if location == "revoked" {
				serialKey := storage.HexSerial(record.Serial)
				if _, exists := seenRevoked[serialKey]; exists {
					return storage.ErrConflict
				}
				seenRevoked[serialKey] = struct{}{}
			}
		}
	}
	return nil
}

func sortLifecycleStateRecords(records []storage.LifecycleRecord) {
	sort.Slice(records, func(i, j int) bool {
		if comparison := records[i].Serial.Cmp(records[j].Serial); comparison != 0 {
			return comparison < 0
		}
		return records[i].Name < records[j].Name
	})
}

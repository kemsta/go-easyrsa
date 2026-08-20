package fs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func (l *LifecycleStorage) ExportState() (state storage.LifecycleState, err error) {
	err = l.withRoot(func(root *os.Root) error {
		var err error
		state.Expired, err = exportNamedLifecycleDirectory(root, "expired")
		if err != nil {
			return err
		}
		state.Renewed, err = exportRenewedLifecycle(root)
		if err != nil {
			return err
		}
		state.Revoked, err = exportRevokedLifecycle(root)
		return err
	})
	if errors.Is(err, storage.ErrNotFound) {
		return storage.LifecycleState{}, nil
	}
	return state, err
}

func exportNamedLifecycleDirectory(root *os.Root, relativeDirectory string) (records []storage.LifecycleRecord, err error) {
	directory, err := root.Open(relativeDirectory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".crt")
		if err := storage.ValidateEntityName(name); err != nil {
			return nil, err
		}
		certificatePEM, err := readLifecycleRootFile(root, filepath.Join(relativeDirectory, entry.Name()))
		if err != nil {
			return nil, err
		}
		serial, err := (&cert.Pair{Name: name, CertPEM: certificatePEM}).Serial()
		if err != nil {
			return nil, err
		}
		record := storage.LifecycleRecord{Name: name, Serial: new(big.Int).Set(serial), CertificatePEM: certificatePEM}
		if key, err := readLifecycleRootFile(root, filepath.Join("private", name+".key")); err == nil {
			record.PrivateKeyPEM = key
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		if request, err := readLifecycleRootFile(root, filepath.Join("reqs", name+".req")); err == nil {
			record.CSRPEM = request
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		records = append(records, record)
	}
	sortLifecycleStateRecords(records)
	return records, nil
}

func exportRenewedLifecycle(root *os.Root) ([]storage.LifecycleRecord, error) {
	archives, err := listRenewalArchives(root)
	if err != nil {
		return nil, err
	}
	if len(archives) == 0 {
		return nil, nil
	}
	records := make([]storage.LifecycleRecord, 0, len(archives))
	for _, archive := range archives {
		name := archive.Name
		if archive.Source == storage.RenewalArchiveBySerial {
			certificate, err := (&cert.Pair{CertPEM: archive.CertificatePEM}).Certificate()
			if err != nil {
				return nil, err
			}
			name = certificate.Subject.CommonName
			if err := storage.ValidateEntityName(name); err != nil {
				return nil, err
			}
		}
		record := storage.LifecycleRecord{
			Name:           name,
			Serial:         new(big.Int).Set(archive.Serial),
			CertificatePEM: append([]byte(nil), archive.CertificatePEM...),
			RenewalSource:  archive.Source,
		}
		if archive.Source == storage.RenewalArchiveIssued {
			if key, err := readLifecycleRootFile(root, filepath.Join("private", name+".key")); err == nil {
				record.PrivateKeyPEM = key
			} else if !errors.Is(err, storage.ErrNotFound) {
				return nil, err
			}
			if request, err := readLifecycleRootFile(root, filepath.Join("reqs", name+".req")); err == nil {
				record.CSRPEM = request
			} else if !errors.Is(err, storage.ErrNotFound) {
				return nil, err
			}
		}
		records = append(records, record)
	}
	sortLifecycleStateRecords(records)
	return records, nil
}

func exportRevokedLifecycle(root *os.Root) (records []storage.LifecycleRecord, err error) {
	directoryName := filepath.Join("revoked", "certs_by_serial")
	directory, err := root.Open(directoryName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		serialHex := strings.TrimSuffix(entry.Name(), ".crt")
		serial := new(big.Int)
		if _, ok := serial.SetString(serialHex, 16); !ok || serial.Sign() <= 0 {
			return nil, fmt.Errorf("storage/fs: invalid revoked serial %q", serialHex)
		}
		certificatePEM, err := readLifecycleRootFile(root, filepath.Join(directoryName, entry.Name()))
		if err != nil {
			return nil, err
		}
		name, err := lifecycleNameForSerial(root, serial, certificatePEM)
		if err != nil {
			return nil, err
		}
		_, markerErr := root.Stat(filepath.Join("certs_by_serial", storage.HexSerial(serial)+".revoked-assets"))
		assetsArchived := markerErr == nil
		if markerErr != nil && !errors.Is(markerErr, fs.ErrNotExist) {
			return nil, markerErr
		}
		if !assetsArchived {
			for _, candidate := range []string{
				filepath.Join("revoked", "private_by_serial", storage.HexSerial(serial)+".key"),
				filepath.Join("revoked", "reqs_by_serial", storage.HexSerial(serial)+".req"),
			} {
				if _, err := root.Stat(candidate); err == nil {
					assetsArchived = true
					break
				} else if !errors.Is(err, fs.ErrNotExist) {
					return nil, err
				}
			}
		}
		record := storage.LifecycleRecord{Name: name, Serial: new(big.Int).Set(serial), CertificatePEM: certificatePEM, AssetsArchived: assetsArchived}
		keyPath := filepath.Join("private", name+".key")
		requestPath := filepath.Join("reqs", name+".req")
		if assetsArchived {
			keyPath = filepath.Join("revoked", "private_by_serial", storage.HexSerial(serial)+".key")
			requestPath = filepath.Join("revoked", "reqs_by_serial", storage.HexSerial(serial)+".req")
		}
		if key, err := readLifecycleRootFile(root, keyPath); err == nil {
			record.PrivateKeyPEM = key
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		if request, err := readLifecycleRootFile(root, requestPath); err == nil {
			record.CSRPEM = request
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		records = append(records, record)
	}
	sortLifecycleStateRecords(records)
	return records, nil
}

func lifecycleNameForSerial(root *os.Root, serial *big.Int, certificatePEM []byte) (string, error) {
	if sidecar, err := root.ReadFile(filepath.Join("certs_by_serial", storage.HexSerial(serial)+".name")); err == nil {
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
	return l.withRoot(func(root *os.Root) error {
		for _, relative := range []string{"expired", "renewed", "revoked"} {
			if err := root.RemoveAll(relative); err != nil {
				return err
			}
		}
		for _, relative := range []string{filepath.Join("renewed", "issued"), filepath.Join("renewed", "certs_by_serial")} {
			if err := root.MkdirAll(relative, 0o755); err != nil {
				return err
			}
		}
		for _, record := range state.Expired {
			if err := writeLifecycleStateRecord(root, filepath.Join("expired", record.Name+".crt"), record, false); err != nil {
				return err
			}
			if err := restoreLifecycleAssets(root, record); err != nil {
				return err
			}
			if err := removeMatchingCurrentLifecycle(root, record, false); err != nil {
				return err
			}
		}
		for _, record := range state.Renewed {
			source := record.RenewalSource
			if source == "" {
				source = storage.RenewalArchiveIssued
			}
			certificatePath := filepath.Join("renewed", "issued", record.Name+".crt")
			if source == storage.RenewalArchiveBySerial {
				certificatePath = filepath.Join("renewed", "certs_by_serial", storage.HexSerial(record.Serial)+".crt")
			}
			if source == storage.RenewalArchiveBySerial {
				if err := writeLifecycleCertificateExclusive(root, certificatePath, record.CertificatePEM); err != nil {
					return err
				}
			} else if err := writeLifecycleStateRecord(root, certificatePath, record, false); err != nil {
				return err
			}
			if source == storage.RenewalArchiveIssued {
				if err := restoreLifecycleAssets(root, record); err != nil {
					return err
				}
			}
		}
		for _, record := range state.Revoked {
			if err := writeLifecycleStateRecord(root, filepath.Join("revoked", "certs_by_serial", storage.HexSerial(record.Serial)+".crt"), record, true); err != nil {
				return err
			}
			if !record.AssetsArchived {
				if err := restoreLifecycleAssets(root, record); err != nil {
					return err
				}
			}
			if err := removeMatchingCurrentLifecycle(root, record, record.AssetsArchived); err != nil {
				return err
			}
		}
		return nil
	})
}

func writeLifecycleStateRecord(root *os.Root, certificatePath string, record storage.LifecycleRecord, revoked bool) error {
	if err := writeLifecycleCertificateExclusive(root, certificatePath, record.CertificatePEM); err != nil {
		return err
	}
	hexSerial := storage.HexSerial(record.Serial)
	if err := writeLifecycleRootFile(root, filepath.Join("certs_by_serial", hexSerial+".name"), []byte(record.Name), 0o600); err != nil {
		return err
	}
	if !revoked || !record.AssetsArchived {
		return nil
	}
	if err := writeLifecycleRootFile(root, filepath.Join("certs_by_serial", hexSerial+".revoked-assets"), []byte("issued"), 0o600); err != nil {
		return err
	}
	if len(record.PrivateKeyPEM) > 0 {
		if err := writeLifecycleRootFile(root, filepath.Join("revoked", "private_by_serial", hexSerial+".key"), record.PrivateKeyPEM, 0o600); err != nil {
			return err
		}
	}
	if len(record.CSRPEM) > 0 {
		if err := writeLifecycleRootFile(root, filepath.Join("revoked", "reqs_by_serial", hexSerial+".req"), record.CSRPEM, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeLifecycleCertificateExclusive(root *os.Root, name string, data []byte) (err error) {
	if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return err
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return errors.Join(storage.ErrConflict, err)
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	n, err := file.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func restoreLifecycleAssets(root *os.Root, record storage.LifecycleRecord) error {
	if len(record.PrivateKeyPEM) > 0 {
		if err := writeLifecycleRootFile(root, filepath.Join("private", record.Name+".key"), record.PrivateKeyPEM, 0o600); err != nil {
			return err
		}
	}
	if len(record.CSRPEM) > 0 {
		if err := writeLifecycleRootFile(root, filepath.Join("reqs", record.Name+".req"), record.CSRPEM, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func removeMatchingCurrentLifecycle(root *os.Root, record storage.LifecycleRecord, removeAssets bool) error {
	currentPath := filepath.Join("issued", record.Name+".crt")
	currentPEM, err := root.ReadFile(currentPath)
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
	if err := removeRootIfExists(root, currentPath); err != nil {
		return err
	}
	if removeAssets {
		if err := removeRootIfExists(root, filepath.Join("private", record.Name+".key")); err != nil {
			return err
		}
		if err := removeRootIfExists(root, filepath.Join("reqs", record.Name+".req")); err != nil {
			return err
		}
	}
	return nil
}

func removeRootIfExists(root *os.Root, name string) error {
	err := root.Remove(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func validateLifecycleState(state storage.LifecycleState) error {
	seenLocations := make(map[string]struct{})
	seenRenewed := make(map[string]struct{})
	seenRevoked := make(map[string]struct{})
	for location, records := range map[string][]storage.LifecycleRecord{"expired": state.Expired, "renewed": state.Renewed, "revoked": state.Revoked} {
		for _, record := range records {
			if location != "revoked" && record.AssetsArchived {
				return fmt.Errorf("storage/fs: archived assets are only valid for revoked certificates")
			}
			if location != "renewed" && record.RenewalSource != "" {
				return fmt.Errorf("storage/fs: renewal source is only valid for renewed certificates")
			}
			if err := storage.ValidateEntityName(record.Name); err != nil {
				return err
			}
			if err := storage.ValidateSerial(record.Serial); err != nil {
				return err
			}
			certificate, err := (&cert.Pair{Name: record.Name, CertPEM: record.CertificatePEM}).Certificate()
			if err != nil {
				return err
			}
			if certificate.SerialNumber.Cmp(record.Serial) != 0 {
				return fmt.Errorf("storage/fs: lifecycle serial does not match certificate")
			}

			key := location + "\x00" + record.Name
			if location == "renewed" {
				serialKey := storage.HexSerial(record.Serial)
				if _, exists := seenRenewed[serialKey]; exists {
					return storage.ErrConflict
				}
				seenRenewed[serialKey] = struct{}{}
				source := record.RenewalSource
				if source == "" {
					source = storage.RenewalArchiveIssued
				}
				switch source {
				case storage.RenewalArchiveIssued:
					key += "\x00issued"
				case storage.RenewalArchiveBySerial:
					if len(record.PrivateKeyPEM) > 0 || len(record.CSRPEM) > 0 {
						return fmt.Errorf("storage/fs: historical renewed certificates cannot carry current assets")
					}
					if record.Name != certificate.Subject.CommonName {
						return fmt.Errorf("storage/fs: historical renewed name does not match certificate common name")
					}
					key = location + "\x00" + serialKey + "\x00certs_by_serial"
				default:
					return fmt.Errorf("storage/fs: unsupported renewal source %q", source)
				}
			}
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

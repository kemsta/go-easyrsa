package legacy

import (
	"errors"
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
	root, err := os.OpenRoot(l.pkiDir)
	if errors.Is(err, fs.ErrNotExist) {
		return storage.LifecycleState{}, nil
	}
	if err != nil {
		return storage.LifecycleState{}, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	expired, err := exportLegacyNamedLifecycle(root, "expired")
	if err != nil {
		return storage.LifecycleState{}, err
	}
	renewed, err := exportLegacyRenewedLifecycle(root)
	if err != nil {
		return storage.LifecycleState{}, err
	}
	revoked, err := exportLegacyRevokedLifecycle(root)
	if err != nil {
		return storage.LifecycleState{}, err
	}
	return storage.LifecycleState{Expired: expired, Renewed: renewed, Revoked: revoked}, nil
}

func exportLegacyNamedLifecycle(root *os.Root, directoryName string) (records []storage.LifecycleRecord, err error) {
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
		name := strings.TrimSuffix(entry.Name(), ".crt")
		if err := storage.ValidateEntityName(name); err != nil {
			return nil, err
		}
		certificatePEM, err := readLegacyRegular(root, filepath.Join(directoryName, entry.Name()))
		if err != nil {
			return nil, err
		}
		serial, err := (&cert.Pair{Name: name, CertPEM: certificatePEM}).Serial()
		if err != nil {
			return nil, err
		}
		records = append(records, storage.LifecycleRecord{Name: name, Serial: new(big.Int).Set(serial), CertificatePEM: certificatePEM})
	}
	sortLegacyLifecycleRecords(records)
	return records, nil
}

func exportLegacyRenewedLifecycle(root *os.Root) ([]storage.LifecycleRecord, error) {
	archives, err := listLegacyRenewalArchives(root)
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
		records = append(records, storage.LifecycleRecord{
			Name:           name,
			Serial:         new(big.Int).Set(archive.Serial),
			CertificatePEM: append([]byte(nil), archive.CertificatePEM...),
			RenewalSource:  archive.Source,
		})
	}
	sortLegacyLifecycleRecords(records)
	return records, nil
}

func exportLegacyRevokedLifecycle(root *os.Root) (records []storage.LifecycleRecord, err error) {
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
			continue
		}
		certificatePEM, err := readLegacyRegular(root, filepath.Join(directoryName, entry.Name()))
		if err != nil {
			return nil, err
		}
		name := ""
		if sidecar, err := readLegacyRegular(root, filepath.Join("certs_by_serial", storage.HexSerial(serial)+".name")); err == nil {
			name = strings.TrimSpace(string(sidecar))
		}
		if name == "" {
			certificate, err := (&cert.Pair{CertPEM: certificatePEM}).Certificate()
			if err != nil {
				return nil, err
			}
			name = certificate.Subject.CommonName
		}
		if err := storage.ValidateEntityName(name); err != nil {
			return nil, err
		}
		record := storage.LifecycleRecord{Name: name, Serial: new(big.Int).Set(serial), CertificatePEM: certificatePEM}
		if key, err := readLegacyRegular(root, filepath.Join("revoked", "private_by_serial", storage.HexSerial(serial)+".key")); err == nil {
			record.PrivateKeyPEM = key
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if request, err := readLegacyRegular(root, filepath.Join("revoked", "reqs_by_serial", storage.HexSerial(serial)+".req")); err == nil {
			record.CSRPEM = request
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		record.AssetsArchived = len(record.PrivateKeyPEM) > 0 || len(record.CSRPEM) > 0
		records = append(records, record)
	}
	sortLegacyLifecycleRecords(records)
	return records, nil
}

func sortLegacyLifecycleRecords(records []storage.LifecycleRecord) {
	sort.Slice(records, func(i, j int) bool {
		if comparison := records[i].Serial.Cmp(records[j].Serial); comparison != 0 {
			return comparison < 0
		}
		return records[i].Name < records[j].Name
	})
}

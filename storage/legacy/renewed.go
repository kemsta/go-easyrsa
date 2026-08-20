package legacy

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

func (l *LifecycleStorage) ListRenewed() (archives []storage.RenewalArchive, err error) {
	root, err := os.OpenRoot(l.pkiDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()

	return listLegacyRenewalArchives(root)
}

func listLegacyRenewalArchives(root *os.Root) ([]storage.RenewalArchive, error) {
	var archives []storage.RenewalArchive
	seenSerials := make(map[string]struct{})
	for _, source := range []struct {
		directory string
		kind      storage.RenewalArchiveSource
	}{
		{directory: filepath.Join("renewed", "issued"), kind: storage.RenewalArchiveIssued},
		{directory: filepath.Join("renewed", "certs_by_serial"), kind: storage.RenewalArchiveBySerial},
	} {
		records, err := listLegacyRenewalDirectory(root, source.directory, source.kind)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			serialKey := storage.HexSerial(record.Serial)
			if _, exists := seenSerials[serialKey]; exists {
				return nil, errors.Join(storage.ErrConflict, fmt.Errorf("storage/legacy: duplicate renewed serial %s", serialKey))
			}
			seenSerials[serialKey] = struct{}{}
			archives = append(archives, record)
		}
	}
	sort.Slice(archives, func(i, j int) bool {
		if archives[i].Source != archives[j].Source {
			return archives[i].Source == storage.RenewalArchiveIssued
		}
		if archives[i].Name != archives[j].Name {
			return archives[i].Name < archives[j].Name
		}
		return archives[i].Serial.Cmp(archives[j].Serial) < 0
	})
	return archives, nil
}

func listLegacyRenewalDirectory(root *os.Root, directoryName string, source storage.RenewalArchiveSource) (records []storage.RenewalArchive, err error) {
	directory, err := openLegacyRenewalDirectory(root, directoryName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()

	entries, err := directory.file.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		if err := validateLegacyRenewalDirectoryIdentity(root, directoryName, directory.identities); err != nil {
			return nil, err
		}
		relativePath := filepath.Join(directoryName, entry.Name())
		entryInfo, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !entryInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("storage/legacy: renewed certificate is not regular: %s", relativePath)
		}
		certificatePEM, err := readLegacyRenewalEntry(directory.file, root, relativePath, entry.Name(), entryInfo)
		if err != nil {
			return nil, err
		}
		if err := validateLegacyRenewalDirectoryIdentity(root, directoryName, directory.identities); err != nil {
			return nil, err
		}
		certificateSerial, err := (&cert.Pair{CertPEM: certificatePEM}).Serial()
		if err != nil {
			return nil, fmt.Errorf("storage/legacy: parse renewed certificate %s: %w", relativePath, err)
		}
		record := storage.RenewalArchive{
			Serial:         new(big.Int).Set(certificateSerial),
			CertificatePEM: append([]byte(nil), certificatePEM...),
			Source:         source,
		}
		switch source {
		case storage.RenewalArchiveIssued:
			record.Name = strings.TrimSuffix(entry.Name(), ".crt")
			if err := storage.ValidateEntityName(record.Name); err != nil {
				return nil, err
			}
		case storage.RenewalArchiveBySerial:
			serialText := strings.TrimSuffix(entry.Name(), ".crt")
			filenameSerial, err := parseLegacyRenewalSerial(serialText)
			if err != nil {
				return nil, err
			}
			if filenameSerial.Cmp(certificateSerial) != 0 {
				return nil, fmt.Errorf("storage/legacy: renewed serial filename %s does not match certificate serial %s", serialText, storage.HexSerial(certificateSerial))
			}
		default:
			return nil, fmt.Errorf("storage/legacy: unsupported renewal archive source %q", source)
		}
		records = append(records, record)
	}
	if err := validateLegacyRenewalDirectoryIdentity(root, directoryName, directory.identities); err != nil {
		return nil, err
	}
	return records, nil
}

type legacyRenewalDirectoryIdentity struct {
	name string
	info fs.FileInfo
}

type legacyRenewalDirectory struct {
	file       *os.File
	handles    []*os.File
	identities []legacyRenewalDirectoryIdentity
}

func (d *legacyRenewalDirectory) Close() error {
	var errs []error
	for i := len(d.handles) - 1; i >= 0; i-- {
		errs = append(errs, d.handles[i].Close())
	}
	return errors.Join(errs...)
}

func openLegacyRenewalDirectory(root *os.Root, directoryName string) (*legacyRenewalDirectory, error) {
	components := legacyRenewalDirectoryComponents(directoryName)
	directory := &legacyRenewalDirectory{
		handles:    make([]*os.File, 0, len(components)),
		identities: make([]legacyRenewalDirectoryIdentity, 0, len(components)),
	}
	for i, component := range components {
		expected, err := root.Lstat(component)
		if err != nil {
			_ = directory.Close()
			return nil, err
		}
		if !expected.IsDir() || expected.Mode()&os.ModeSymlink != 0 {
			_ = directory.Close()
			return nil, fmt.Errorf("storage/legacy: renewal archive is not a directory: %s", component)
		}
		openedFile, err := openLegacyRegular(root, component)
		if err != nil {
			_ = directory.Close()
			return nil, err
		}
		opened, err := openedFile.Stat()
		if err != nil {
			_ = openedFile.Close()
			_ = directory.Close()
			return nil, err
		}
		if !opened.IsDir() || !os.SameFile(expected, opened) {
			_ = openedFile.Close()
			_ = directory.Close()
			return nil, fmt.Errorf("storage/legacy: renewal archive changed while opening: %s", component)
		}
		directory.handles = append(directory.handles, openedFile)
		directory.identities = append(directory.identities, legacyRenewalDirectoryIdentity{name: component, info: opened})
		if i == len(components)-1 {
			directory.file = openedFile
		}
	}
	return directory, nil
}

func readLegacyRenewalEntry(directory *os.File, root *os.Root, relativePath, name string, expected fs.FileInfo) (data []byte, err error) {
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return nil, fmt.Errorf("storage/legacy: invalid renewal archive entry %q", name)
	}
	file, err := openLegacyRenewalEntryFile(directory, root, relativePath, name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return nil, fmt.Errorf("storage/legacy: renewed certificate changed while opening: %s", relativePath)
	}
	return io.ReadAll(file)
}

func validateLegacyRenewalDirectoryIdentity(root *os.Root, _ string, expected []legacyRenewalDirectoryIdentity) error {
	for _, identity := range expected {
		current, err := root.Lstat(identity.name)
		if err != nil {
			return err
		}
		if !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(identity.info, current) {
			return fmt.Errorf("storage/legacy: renewal archive directory changed: %s", identity.name)
		}
	}
	return nil
}

func legacyRenewalDirectoryComponents(directoryName string) []string {
	var reversed []string
	for current := filepath.Clean(directoryName); current != "." && current != string(filepath.Separator); current = filepath.Dir(current) {
		reversed = append(reversed, current)
	}
	components := make([]string, len(reversed))
	for i := range reversed {
		components[len(reversed)-1-i] = reversed[i]
	}
	return components
}

func parseLegacyRenewalSerial(value string) (*big.Int, error) {
	if value == "" || strings.Trim(value, "0123456789abcdefABCDEF") != "" {
		return nil, fmt.Errorf("storage/legacy: invalid renewed serial %q", value)
	}
	serial := new(big.Int)
	if _, ok := serial.SetString(value, 16); !ok || serial.Sign() <= 0 {
		return nil, fmt.Errorf("storage/legacy: invalid renewed serial %q", value)
	}
	return serial, nil
}

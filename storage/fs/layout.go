package fs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

// OwnershipProbe checks whether a filesystem directory is empty or already
// belongs to the current fs backend.
type OwnershipProbe struct {
	Dir string
}

func (p OwnershipProbe) Empty() (bool, error) {
	info, err := os.Stat(p.Dir)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("%s exists and is not a directory", p.Dir)
	}
	entries, err := os.ReadDir(p.Dir)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}

func (p OwnershipProbe) Owned() (bool, error) {
	info, err := os.Stat(p.Dir)
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("%s exists and is not a directory", p.Dir)
	}
	entries, err := os.ReadDir(p.Dir)
	if err != nil {
		return false, err
	}
	entryByName := make(map[string]os.DirEntry, len(entries))
	for _, entry := range entries {
		entryByName[entry.Name()] = entry
	}

	// A Go-initialized layout always has all four directories. Requiring the
	// complete set prevents a foreign tree containing only a generic private/
	// or issued/ directory from being reset.
	allGoDirectories := true
	for _, name := range []string{"private", "issued", "reqs", "certs_by_serial"} {
		entry, ok := entryByName[name]
		if !ok || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			allGoDirectories = false
			break
		}
	}
	if allGoDirectories {
		return true, nil
	}

	// A fresh upstream Easy-RSA layout has private/, issued/, reqs/, and the
	// generated vars.example marker before CA metadata exists.
	upstreamDirectories := true
	for _, name := range []string{"private", "issued", "reqs"} {
		entry, ok := entryByName[name]
		if !ok || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			upstreamDirectories = false
			break
		}
	}
	if upstreamDirectories && regularEntry(entryByName["vars.example"]) {
		return true, nil
	}

	hasPKIDirectory := false
	for _, name := range []string{"private", "issued", "reqs", "certs_by_serial", "expired", "renewed", "revoked"} {
		if entry, ok := entryByName[name]; ok && entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			hasPKIDirectory = true
			break
		}
	}
	if hasPKIDirectory && regularEntry(entryByName["index.txt"]) {
		if _, err := NewIndexDB(p.Dir).Query(storage.IndexFilter{}); err == nil {
			return true, nil
		}
	}
	if regularEntry(entryByName["ca.crt"]) {
		data, err := os.ReadFile(filepath.Join(p.Dir, "ca.crt"))
		if err == nil {
			block, _ := pem.Decode(data)
			if block != nil {
				if _, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
					return true, nil
				}
			}
		}
	}
	if hasPKIDirectory && regularEntry(entryByName["serial"]) {
		data, err := os.ReadFile(filepath.Join(p.Dir, "serial"))
		value := strings.TrimSpace(string(data))
		if err == nil && value != "" {
			valid := true
			for _, character := range value {
				if (character < '0' || character > '9') && (character < 'a' || character > 'f') && (character < 'A' || character > 'F') {
					valid = false
					break
				}
			}
			if valid {
				return true, nil
			}
		}
	}
	return false, nil
}

func regularEntry(entry os.DirEntry) bool {
	if entry == nil || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
		return false
	}
	info, err := entry.Info()
	return err == nil && info.Mode().IsRegular()
}

var (
	_ storage.OwnershipValidator = (*KeyStorage)(nil)
	_ storage.OwnershipValidator = (*CSRStorage)(nil)
	_ storage.OwnershipValidator = (*IndexDB)(nil)
	_ storage.OwnershipValidator = (*SerialProvider)(nil)
	_ storage.OwnershipValidator = (*CRLHolder)(nil)
)

package legacy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var legacySerialFilePattern = regexp.MustCompile(`^[0-9A-Fa-f]+\.(crt|key)$`)

// OwnershipProbe checks whether a filesystem directory is empty or already
// belongs to the legacy v1 filesystem backend.
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
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		owned, err := looksLikeLegacyEntityDir(filepath.Join(p.Dir, entry.Name()))
		if err != nil {
			return false, err
		}
		if owned {
			return true, nil
		}
	}
	return false, nil
}

func looksLikeLegacyEntityDir(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if legacySerialFilePattern.MatchString(entry.Name()) {
			return true, nil
		}
	}
	return false, nil
}

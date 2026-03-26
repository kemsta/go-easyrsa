package fs

import (
	"fmt"
	"os"

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
	for _, entry := range entries {
		if isCurrentLayoutMarker(entry.Name(), entry.IsDir()) {
			return true, nil
		}
	}
	return false, nil
}

var (
	_ storage.OwnershipValidator = (*KeyStorage)(nil)
	_ storage.OwnershipValidator = (*CSRStorage)(nil)
	_ storage.OwnershipValidator = (*IndexDB)(nil)
	_ storage.OwnershipValidator = (*SerialProvider)(nil)
	_ storage.OwnershipValidator = (*CRLHolder)(nil)
)

func isCurrentLayoutMarker(name string, isDir bool) bool {
	if isDir {
		switch name {
		case "private", "issued", "reqs", "certs_by_serial", "revoked":
			return true
		}
		return false
	}
	switch name {
	case "index.txt", "ca.crt":
		return true
	default:
		return false
	}
}

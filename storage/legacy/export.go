package legacy

import (
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// ExportPairs streams all legacy pairs without materializing their PEM payloads
// all at once.
func (ks *KeyStorage) ExportPairs(yield func(*cert.Pair) error) error {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	entries, err := os.ReadDir(ks.pkiDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() && safeEntityName(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		dir := filepath.Join(ks.pkiDir, name)
		dirEntries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		type item struct {
			serial    *big.Int
			name      string
			serialHex string
		}
		items := make([]item, 0, len(dirEntries))
		for _, entry := range dirEntries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
				continue
			}
			serialHex := strings.TrimSuffix(entry.Name(), ".crt")
			serial := new(big.Int)
			if _, ok := serial.SetString(serialHex, 16); !ok {
				continue
			}
			items = append(items, item{serial: serial, name: entry.Name(), serialHex: serialHex})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].serial.Cmp(items[j].serial) < 0 })

		for _, item := range items {
			certPEM, err := os.ReadFile(filepath.Join(dir, item.name))
			if err != nil {
				return err
			}
			pair := &cert.Pair{Name: name, CertPEM: certPEM}
			keyPath := filepath.Join(dir, item.serialHex+".key")
			if keyPEM, err := os.ReadFile(keyPath); err == nil {
				pair.KeyPEM = keyPEM
			} else if !os.IsNotExist(err) {
				return err
			}
			if err := yield(pair); err != nil {
				return err
			}
		}
	}

	return nil
}

var _ storage.PairExporter = (*KeyStorage)(nil)

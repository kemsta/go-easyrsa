package fs

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// ExportPairs streams all pairs from the filesystem backend without building a
// full in-memory slice of certificate/key material.
func (ks *KeyStorage) ExportPairs(yield func(*cert.Pair) error) error {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	serialDir := fsJoin(ks.pkiDir, "certs_by_serial")
	entries, err := os.ReadDir(serialDir)
	if err != nil {
		if os.IsNotExist(err) {
			pairs, err := ks.getNamedPairsLocked()
			if err != nil {
				return err
			}
			for _, pair := range pairs {
				if err := yield(pair); err != nil {
					return err
				}
			}
			return nil
		}
		return err
	}

	type item struct {
		serial *big.Int
		name   string
	}
	items := make([]item, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pem") {
			continue
		}
		serialHex := strings.TrimSuffix(entry.Name(), ".pem")
		serial := new(big.Int)
		if _, ok := serial.SetString(serialHex, 16); !ok {
			continue
		}
		items = append(items, item{serial: serial, name: entry.Name()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].serial.Cmp(items[j].serial) < 0 })

	for _, item := range items {
		certPEM, err := os.ReadFile(filepath.Join(serialDir, item.name))
		if err != nil {
			return err
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			continue
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		serialHex := storage.HexSerial(item.serial)
		name := crt.Subject.CommonName
		if data, err := os.ReadFile(filepath.Join(serialDir, serialHex+".name")); err == nil {
			if n := strings.TrimSpace(string(data)); n != "" {
				name = n
			}
		}
		pair := &cert.Pair{Name: name, CertPEM: certPEM}
		if keyPEM, err := os.ReadFile(ks.keyPath(name)); err == nil {
			pair.KeyPEM = keyPEM
		}
		if err := yield(pair); err != nil {
			return err
		}
	}

	return nil
}

var _ storage.PairExporter = (*KeyStorage)(nil)

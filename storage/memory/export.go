package memory

import (
	"sort"

	"github.com/kemsta/go-easyrsa/cert"
	"github.com/kemsta/go-easyrsa/storage"
)

// ExportPairs streams all in-memory pairs in ascending serial order.
func (ks *KeyStorage) ExportPairs(yield func(*cert.Pair) error) error {
	ks.s.mu.RLock()
	defer ks.s.mu.RUnlock()

	var pairs []*cert.Pair
	for _, byName := range ks.s.pairs {
		for _, pair := range byName {
			cp := &cert.Pair{Name: pair.Name}
			if pair.CertPEM != nil {
				cp.CertPEM = append([]byte(nil), pair.CertPEM...)
			}
			if pair.KeyPEM != nil {
				cp.KeyPEM = append([]byte(nil), pair.KeyPEM...)
			}
			pairs = append(pairs, cp)
		}
	}

	sort.Slice(pairs, func(i, j int) bool {
		si, errI := pairs[i].Serial()
		sj, errJ := pairs[j].Serial()
		switch {
		case errI != nil && errJ != nil:
			return pairs[i].Name < pairs[j].Name
		case errI != nil:
			return true
		case errJ != nil:
			return false
		}
		if cmp := si.Cmp(sj); cmp != 0 {
			return cmp < 0
		}
		return pairs[i].Name < pairs[j].Name
	})

	for _, pair := range pairs {
		if err := yield(pair); err != nil {
			return err
		}
	}
	return nil
}

var _ storage.PairExporter = (*KeyStorage)(nil)

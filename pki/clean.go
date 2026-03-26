package pki

import (
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// Cleaner is an optional interface that storage implementations may satisfy
// to support removal of orphaned files not referenced by the index.
type Cleaner interface {
	CleanOrphans(knownSerials map[string]bool) error
}

// Clean removes orphaned certificate and key files from storage that are not
// referenced by any index entry. Orphans can appear when a crash occurs after
// writing files but before committing the index entry.
//
// If the underlying storage does not implement Cleaner, Clean is a no-op.
func (p *PKI) Clean() error {
	entries, err := p.index.Query(storage.IndexFilter{})
	if err != nil {
		return err
	}
	knownSerials := make(map[string]bool, len(entries))
	for _, e := range entries {
		knownSerials[storage.HexSerial(e.Serial)] = true
	}
	if c, ok := p.storage.(Cleaner); ok {
		return c.CleanOrphans(knownSerials)
	}
	return nil
}

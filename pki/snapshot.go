package pki

import (
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// Snapshot is a storage-agnostic PKI transfer representation for metadata.
// Certificate pairs are exported separately via ExportPairs.
type Snapshot struct {
	CAName     string
	Index      []storage.IndexEntry
	CRLPEM     []byte
	NextSerial *big.Int
}

// ExportSnapshot exports PKI metadata in a storage-agnostic form.
func (p *PKI) ExportSnapshot() (*Snapshot, error) {
	entries, err := p.index.Query(storage.IndexFilter{})
	if err != nil {
		return nil, err
	}
	entries = cloneAndSortEntries(entries)

	crlPEM, err := exportCRLPEM(p.crlHolder)
	if err != nil {
		return nil, err
	}

	return &Snapshot{
		CAName:     p.config.CAName,
		Index:      entries,
		CRLPEM:     crlPEM,
		NextSerial: nextSerialFromEntries(entries),
	}, nil
}

// ExportPairs streams certificate pairs in ascending serial order where possible.
func (p *PKI) ExportPairs(yield func(*cert.Pair) error) error {
	if yield == nil {
		return errors.New("pki: yield must not be nil")
	}
	if exporter, ok := p.storage.(storage.PairExporter); ok {
		return exporter.ExportPairs(func(pair *cert.Pair) error {
			return yield(clonePair(pair))
		})
	}
	pairs, err := p.storage.GetAll()
	if err != nil {
		return err
	}
	pairs = cloneAndSortPairs(pairs)
	for _, pair := range pairs {
		if err := yield(pair); err != nil {
			return err
		}
	}
	return nil
}

// ImportSnapshot imports PKI metadata and a streamed pair set into this PKI.
// The target PKI is expected to be empty/newly created.
func (p *PKI) ImportSnapshot(snapshot *Snapshot, stream storage.PairStream) error {
	if snapshot == nil {
		return errors.New("pki: snapshot must not be nil")
	}
	if snapshot.CAName == "" {
		return errors.New("pki: snapshot CA name must not be empty")
	}
	if stream == nil {
		return errors.New("pki: pair stream must not be nil")
	}
	if p.config.CAName != snapshot.CAName {
		return fmt.Errorf("pki: target CAName %q does not match snapshot CAName %q", p.config.CAName, snapshot.CAName)
	}

	if replacer, ok := p.storage.(storage.PairReplacer); ok {
		if err := replacer.ReplacePairs(stream); err != nil {
			return err
		}
	} else {
		if err := stream(func(pair *cert.Pair) error {
			return p.storage.Put(clonePair(pair))
		}); err != nil {
			return err
		}
	}

	if replacer, ok := p.index.(storage.IndexReplacer); ok {
		if err := replacer.ReplaceAll(snapshot.Index); err != nil {
			return err
		}
	} else {
		return errors.New("pki: target index does not support snapshot import")
	}

	if len(snapshot.CRLPEM) > 0 {
		if err := p.crlHolder.Put(snapshot.CRLPEM); err != nil {
			return err
		}
	}

	if snapshot.NextSerial != nil {
		setter, ok := p.serial.(storage.SerialSetter)
		if !ok {
			return errors.New("pki: target serial provider does not support snapshot import")
		}
		if err := setter.SetNext(snapshot.NextSerial); err != nil {
			return err
		}
	}

	return nil
}

func exportCRLPEM(holder storage.CRLHolder) ([]byte, error) {
	crl, err := holder.Get()
	if err != nil {
		return nil, err
	}
	if crl == nil || len(crl.Raw) == 0 {
		return nil, nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.Raw}), nil
}

func nextSerialFromEntries(entries []storage.IndexEntry) *big.Int {
	maxSerial := big.NewInt(0)
	for _, entry := range entries {
		if entry.Serial != nil && entry.Serial.Cmp(maxSerial) > 0 {
			maxSerial = new(big.Int).Set(entry.Serial)
		}
	}
	if maxSerial.Sign() == 0 {
		return big.NewInt(1)
	}
	return new(big.Int).Add(maxSerial, big.NewInt(1))
}

func cloneAndSortPairs(pairs []*cert.Pair) []*cert.Pair {
	out := make([]*cert.Pair, 0, len(pairs))
	for _, pair := range pairs {
		if pair == nil {
			continue
		}
		out = append(out, clonePair(pair))
	}
	sort.Slice(out, func(i, j int) bool {
		si, errI := out[i].Serial()
		sj, errJ := out[j].Serial()
		switch {
		case errI != nil && errJ != nil:
			return out[i].Name < out[j].Name
		case errI != nil:
			return true
		case errJ != nil:
			return false
		}
		if cmp := si.Cmp(sj); cmp != 0 {
			return cmp < 0
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func cloneAndSortEntries(entries []storage.IndexEntry) []storage.IndexEntry {
	out := make([]storage.IndexEntry, len(entries))
	for i, entry := range entries {
		out[i] = entry
		if entry.Serial != nil {
			out[i].Serial = new(big.Int).Set(entry.Serial)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		si, sj := out[i].Serial, out[j].Serial
		switch {
		case si == nil && sj == nil:
			return out[i].Subject.CommonName < out[j].Subject.CommonName
		case si == nil:
			return true
		case sj == nil:
			return false
		}
		if cmp := si.Cmp(sj); cmp != 0 {
			return cmp < 0
		}
		return out[i].Subject.CommonName < out[j].Subject.CommonName
	})
	return out
}

func clonePair(pair *cert.Pair) *cert.Pair {
	if pair == nil {
		return nil
	}
	cp := &cert.Pair{Name: pair.Name}
	if pair.CertPEM != nil {
		cp.CertPEM = append([]byte(nil), pair.CertPEM...)
	}
	if pair.KeyPEM != nil {
		cp.KeyPEM = append([]byte(nil), pair.KeyPEM...)
	}
	return cp
}

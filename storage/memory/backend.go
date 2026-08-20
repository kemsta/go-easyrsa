package memory

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"sync"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// Backend is a transactional in-memory storage backend.
type Backend struct {
	mu sync.RWMutex
	s  *store
}

// NewBackend creates an empty transactional in-memory backend.
func NewBackend() *Backend {
	return &Backend{s: newStore()}
}

func (b *Backend) EnsureLayout() error { return nil }

func (b *Backend) Initialize(reset bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !reset && !b.s.empty() {
		return storage.ErrConflict
	}
	b.s.replace(newStore())
	return nil
}

func (b *Backend) ReadOnly() bool { return false }

func (b *Backend) Empty() (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.s.empty(), nil
}

func (b *Backend) Owned() (bool, error) { return true, nil }

func (b *Backend) View(fn func(storage.Components) error) error {
	b.mu.RLock()
	snapshot := b.s.clone()
	b.mu.RUnlock()
	return fn(storage.ReadOnlyComponents(newComponents(snapshot)))
}

func (b *Backend) Update(fn func(storage.Components) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	candidate := b.s.clone()
	if err := fn(newComponents(candidate)); err != nil {
		return err
	}
	b.s.replace(candidate)
	return nil
}

type components struct {
	keys      *KeyStorage
	csrs      *CSRStorage
	index     *IndexDB
	serials   *SerialProvider
	crls      *CRLHolder
	artifacts *ArtifactStorage
	lifecycle *LifecycleStorage
}

func newComponents(s *store) *components {
	return &components{
		keys:      &KeyStorage{s},
		csrs:      &CSRStorage{s},
		index:     &IndexDB{s},
		serials:   &SerialProvider{s},
		crls:      &CRLHolder{s},
		artifacts: &ArtifactStorage{s},
		lifecycle: &LifecycleStorage{s},
	}
}

func (c *components) Keys() storage.KeyStorage            { return c.keys }
func (c *components) CSRs() storage.CSRStorage            { return c.csrs }
func (c *components) Index() storage.IndexDB              { return c.index }
func (c *components) Serials() storage.SerialProvider     { return c.serials }
func (c *components) CRLs() storage.CRLHolder             { return c.crls }
func (c *components) Artifacts() storage.ArtifactStorage  { return c.artifacts }
func (c *components) Lifecycle() storage.LifecycleStorage { return c.lifecycle }

func (s *store) replace(source *store) {
	replacement := source.clone()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pairs = replacement.pairs
	s.bySerial = replacement.bySerial
	s.csrs = replacement.csrs
	s.pendingKeys = replacement.pendingKeys
	s.entries = replacement.entries
	s.crlPEM = replacement.crlPEM
	s.serial = replacement.serial
	s.artifacts = replacement.artifacts
	s.expired = replacement.expired
	s.renewed = replacement.renewed
	s.revokedCerts = replacement.revokedCerts
	s.revokedKeys = replacement.revokedKeys
	s.revokedCSRs = replacement.revokedCSRs
	s.revokedNames = replacement.revokedNames
	s.unavailable = replacement.unavailable
}

func (s *store) clone() *store {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cloned := newStore()
	cloned.serial = cloneBigInt(s.serial)
	cloned.crlPEM = cloneBytes(s.crlPEM)

	for name, pairs := range s.pairs {
		cloned.pairs[name] = make([]*cert.Pair, 0, len(pairs))
		for _, pair := range pairs {
			cp := clonePair(pair)
			cloned.pairs[name] = append(cloned.pairs[name], cp)
			if cp.CertPEM != nil {
				if serial, err := cp.Serial(); err == nil {
					cloned.bySerial[hexSerial(serial)] = cp
				}
			}
		}
	}
	for serial, pair := range s.bySerial {
		if _, ok := cloned.bySerial[serial]; !ok {
			cloned.bySerial[serial] = clonePair(pair)
		}
	}
	for name, csr := range s.csrs {
		cloned.csrs[name] = cloneBytes(csr)
	}
	cloneByteMap(cloned.pendingKeys, s.pendingKeys)
	cloned.entries = make([]storage.IndexEntry, len(s.entries))
	for i, entry := range s.entries {
		cloned.entries[i] = cloneIndexEntry(entry)
	}
	for name, artifact := range s.artifacts {
		cloned.artifacts[name] = cloneArtifact(artifact)
	}
	cloneByteMap(cloned.expired, s.expired)
	cloneByteMap(cloned.renewed, s.renewed)
	cloneByteMap(cloned.revokedCerts, s.revokedCerts)
	cloneByteMap(cloned.revokedKeys, s.revokedKeys)
	cloneByteMap(cloned.revokedCSRs, s.revokedCSRs)
	for serial, name := range s.revokedNames {
		cloned.revokedNames[serial] = name
	}
	for name, unavailable := range s.unavailable {
		cloned.unavailable[name] = unavailable
	}
	return cloned
}

func clonePair(pair *cert.Pair) *cert.Pair {
	if pair == nil {
		return nil
	}
	return &cert.Pair{
		Name:    pair.Name,
		CertPEM: cloneBytes(pair.CertPEM),
		KeyPEM:  cloneBytes(pair.KeyPEM),
	}
}

func cloneIndexEntry(entry storage.IndexEntry) storage.IndexEntry {
	entry.Serial = cloneBigInt(entry.Serial)
	entry.Subject = cloneName(entry.Subject)
	return entry
}

func cloneName(name pkix.Name) pkix.Name {
	name.Country = append([]string(nil), name.Country...)
	name.Organization = append([]string(nil), name.Organization...)
	name.OrganizationalUnit = append([]string(nil), name.OrganizationalUnit...)
	name.Locality = append([]string(nil), name.Locality...)
	name.Province = append([]string(nil), name.Province...)
	name.StreetAddress = append([]string(nil), name.StreetAddress...)
	name.PostalCode = append([]string(nil), name.PostalCode...)
	name.Names = append([]pkix.AttributeTypeAndValue(nil), name.Names...)
	name.ExtraNames = append([]pkix.AttributeTypeAndValue(nil), name.ExtraNames...)
	for i := range name.Names {
		name.Names[i].Type = append(asn1.ObjectIdentifier(nil), name.Names[i].Type...)
		name.Names[i].Value = cloneAttributeValue(name.Names[i].Value)
	}
	for i := range name.ExtraNames {
		name.ExtraNames[i].Type = append(asn1.ObjectIdentifier(nil), name.ExtraNames[i].Type...)
		name.ExtraNames[i].Value = cloneAttributeValue(name.ExtraNames[i].Value)
	}
	return name
}

func cloneAttributeValue(value any) any {
	switch value := value.(type) {
	case []byte:
		return cloneBytes(value)
	case []string:
		return append([]string(nil), value...)
	case asn1.ObjectIdentifier:
		return append(asn1.ObjectIdentifier(nil), value...)
	case asn1.RawValue:
		value.Bytes = cloneBytes(value.Bytes)
		value.FullBytes = cloneBytes(value.FullBytes)
		return value
	case []any:
		cloned := make([]any, len(value))
		for i := range value {
			cloned[i] = cloneAttributeValue(value[i])
		}
		return cloned
	default:
		return value
	}
}

func cloneArtifact(artifact storage.Artifact) storage.Artifact {
	artifact.Data = cloneBytes(artifact.Data)
	return artifact
}

func cloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

func cloneByteMap(dst, src map[string][]byte) {
	for key, value := range src {
		dst[key] = cloneBytes(value)
	}
}

var (
	_ storage.Backend            = (*Backend)(nil)
	_ storage.OwnershipValidator = (*Backend)(nil)
	_ storage.Components         = (*components)(nil)
)

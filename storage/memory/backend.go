package memory

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"time"

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

func (c *components) Empty() (bool, error) {
	c.keys.s.mu.RLock()
	defer c.keys.s.mu.RUnlock()
	return c.keys.s.empty(), nil
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
	s.renewedBySerial = replacement.renewedBySerial
	s.revokedCerts = replacement.revokedCerts
	s.revokedKeys = replacement.revokedKeys
	s.revokedCSRs = replacement.revokedCSRs
	s.revokedNames = replacement.revokedNames
	s.revokedAssetsArchived = replacement.revokedAssetsArchived
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
	cloneByteMap(cloned.renewedBySerial, s.renewedBySerial)
	cloneByteMap(cloned.revokedCerts, s.revokedCerts)
	cloneByteMap(cloned.revokedKeys, s.revokedKeys)
	cloneByteMap(cloned.revokedCSRs, s.revokedCSRs)
	for serial, name := range s.revokedNames {
		cloned.revokedNames[serial] = name
	}
	for serial, archived := range s.revokedAssetsArchived {
		cloned.revokedAssetsArchived[serial] = archived
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
	cloned, err := cloneIndexEntryChecked(entry)
	if err != nil {
		panic(fmt.Sprintf("storage/memory: invalid stored index attribute: %v", err))
	}
	return cloned
}

func cloneIndexEntryChecked(entry storage.IndexEntry) (storage.IndexEntry, error) {
	entry.Serial = cloneBigInt(entry.Serial)
	name, err := cloneNameChecked(entry.Subject)
	if err != nil {
		return storage.IndexEntry{}, err
	}
	entry.Subject = name
	return entry, nil
}

func cloneNameChecked(name pkix.Name) (pkix.Name, error) {
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
		value, err := cloneAttributeValue(name.Names[i].Value)
		if err != nil {
			return pkix.Name{}, err
		}
		name.Names[i].Value = value
	}
	for i := range name.ExtraNames {
		name.ExtraNames[i].Type = append(asn1.ObjectIdentifier(nil), name.ExtraNames[i].Type...)
		value, err := cloneAttributeValue(name.ExtraNames[i].Value)
		if err != nil {
			return pkix.Name{}, err
		}
		name.ExtraNames[i].Value = value
	}
	return name, nil
}

func cloneAttributeValue(value any) (any, error) {
	switch value := value.(type) {
	case nil:
		return nil, nil
	case asn1.ObjectIdentifier:
		return append(asn1.ObjectIdentifier(nil), value...), nil
	case asn1.RawValue:
		value.Bytes = cloneBytes(value.Bytes)
		value.FullBytes = cloneBytes(value.FullBytes)
		return value, nil
	case asn1.BitString:
		value.Bytes = cloneBytes(value.Bytes)
		return value, nil
	case big.Int:
		return *new(big.Int).Set(&value), nil
	case *big.Int:
		return cloneBigInt(value), nil
	case time.Time:
		return value, nil
	}
	cloned, err := cloneAttributeReflect(reflect.ValueOf(value), make(map[cloneVisit]bool))
	if err != nil {
		return nil, err
	}
	return cloned.Interface(), nil
}

type cloneVisit struct {
	typeOf  reflect.Type
	pointer uintptr
}

func cloneAttributeReflect(value reflect.Value, stack map[cloneVisit]bool) (reflect.Value, error) {
	if !value.IsValid() {
		return value, nil
	}
	switch value.Kind() {
	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		return value, nil
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type()), nil
		}
		cloned, err := cloneAttributeReflect(value.Elem(), stack)
		if err != nil {
			return reflect.Value{}, err
		}
		wrapped := reflect.New(value.Type()).Elem()
		wrapped.Set(cloned)
		return wrapped, nil
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type()), nil
		}
		release, err := enterCloneValue(value, stack)
		if err != nil {
			return reflect.Value{}, err
		}
		defer release()
		cloned, err := cloneAttributeReflect(value.Elem(), stack)
		if err != nil {
			return reflect.Value{}, err
		}
		pointer := reflect.New(value.Type().Elem())
		pointer.Elem().Set(cloned)
		return pointer, nil
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type()), nil
		}
		release, err := enterCloneValue(value, stack)
		if err != nil {
			return reflect.Value{}, err
		}
		defer release()
		cloned := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for i := 0; i < value.Len(); i++ {
			element, err := cloneAttributeReflect(value.Index(i), stack)
			if err != nil {
				return reflect.Value{}, err
			}
			cloned.Index(i).Set(element)
		}
		return cloned, nil
	case reflect.Array:
		cloned := reflect.New(value.Type()).Elem()
		for i := 0; i < value.Len(); i++ {
			element, err := cloneAttributeReflect(value.Index(i), stack)
			if err != nil {
				return reflect.Value{}, err
			}
			cloned.Index(i).Set(element)
		}
		return cloned, nil
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type()), nil
		}
		release, err := enterCloneValue(value, stack)
		if err != nil {
			return reflect.Value{}, err
		}
		defer release()
		cloned := reflect.MakeMapWithSize(value.Type(), value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			key, err := cloneAttributeReflect(iterator.Key(), stack)
			if err != nil {
				return reflect.Value{}, err
			}
			mapValue, err := cloneAttributeReflect(iterator.Value(), stack)
			if err != nil {
				return reflect.Value{}, err
			}
			cloned.SetMapIndex(key, mapValue)
		}
		return cloned, nil
	case reflect.Struct:
		cloned := reflect.New(value.Type()).Elem()
		for i := 0; i < value.NumField(); i++ {
			if !cloned.Field(i).CanSet() || value.Type().Field(i).PkgPath != "" {
				return reflect.Value{}, fmt.Errorf("unsupported mutable attribute struct %s", value.Type())
			}
			field, err := cloneAttributeReflect(value.Field(i), stack)
			if err != nil {
				return reflect.Value{}, err
			}
			cloned.Field(i).Set(field)
		}
		return cloned, nil
	default:
		return reflect.Value{}, fmt.Errorf("unsupported mutable attribute type %s", value.Type())
	}
}

func enterCloneValue(value reflect.Value, stack map[cloneVisit]bool) (func(), error) {
	pointer := value.Pointer()
	if pointer == 0 {
		return func() {}, nil
	}
	visit := cloneVisit{typeOf: value.Type(), pointer: pointer}
	if stack[visit] {
		return nil, fmt.Errorf("cyclic mutable attribute value %s", value.Type())
	}
	stack[visit] = true
	return func() { delete(stack, visit) }, nil
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

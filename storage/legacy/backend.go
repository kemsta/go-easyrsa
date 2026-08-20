package legacy

import (
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

// Backend exposes the legacy v1 layout through the aggregate read-only
// backend contract.
type Backend struct {
	pkiDir     string
	components *components
}

// NewBackend creates a read-only legacy backend.
func NewBackend(pkiDir, caName string) *Backend {
	keys := NewKeyStorage(pkiDir, caName)
	crls := NewCRLHolder(pkiDir)
	return &Backend{
		pkiDir: pkiDir,
		components: &components{
			keys:      keys,
			csrs:      NewCSRStorage(pkiDir),
			index:     NewIndexDB(keys, crls),
			serials:   NewSerialProvider(pkiDir),
			crls:      crls,
			artifacts: &ArtifactStorage{pkiDir: pkiDir},
			lifecycle: &LifecycleStorage{pkiDir: pkiDir},
		},
	}
}

func (b *Backend) EnsureLayout() error                         { return storage.ErrReadOnly }
func (b *Backend) Initialize(bool) error                       { return storage.ErrReadOnly }
func (b *Backend) ReadOnly() bool                              { return true }
func (b *Backend) Empty() (bool, error)                        { return OwnershipProbe{Dir: b.pkiDir}.Empty() }
func (b *Backend) Owned() (bool, error)                        { return OwnershipProbe{Dir: b.pkiDir}.Owned() }
func (b *Backend) Update(func(storage.Components) error) error { return storage.ErrReadOnly }

func (b *Backend) View(fn func(storage.Components) error) error {
	if err := storage.ValidateOwnership(OwnershipProbe{Dir: b.pkiDir}); err != nil {
		return err
	}
	return fn(storage.ReadOnlyComponents(b.components))
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

func (c *components) Keys() storage.KeyStorage            { return c.keys }
func (c *components) CSRs() storage.CSRStorage            { return c.csrs }
func (c *components) Index() storage.IndexDB              { return c.index }
func (c *components) Serials() storage.SerialProvider     { return c.serials }
func (c *components) CRLs() storage.CRLHolder             { return c.crls }
func (c *components) Artifacts() storage.ArtifactStorage  { return c.artifacts }
func (c *components) Lifecycle() storage.LifecycleStorage { return c.lifecycle }

// ArtifactStorage permits confined legacy reads and rejects mutations.
type ArtifactStorage struct{ pkiDir string }

func (a *ArtifactStorage) PutArtifact(storage.Artifact) error { return storage.ErrReadOnly }
func (a *ArtifactStorage) DeleteArtifact(string) error        { return storage.ErrReadOnly }
func (a *ArtifactStorage) GetArtifact(name string) (storage.Artifact, error) {
	if err := storage.ValidateArtifactPath(name); err != nil {
		return storage.Artifact{}, err
	}
	root, err := os.OpenRoot(a.pkiDir)
	if errors.Is(err, fs.ErrNotExist) {
		return storage.Artifact{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.Artifact{}, err
	}
	defer root.Close()
	relative := filepath.FromSlash(name)
	info, err := root.Lstat(relative)
	if errors.Is(err, fs.ErrNotExist) {
		return storage.Artifact{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.Artifact{}, err
	}
	data, err := readLegacyRegular(root, relative)
	if err != nil {
		return storage.Artifact{}, err
	}
	visibility := storage.ArtifactPublic
	if info.Mode().Perm()&0o077 == 0 {
		visibility = storage.ArtifactPrivate
	}
	return storage.Artifact{Path: name, Data: data, Visibility: visibility}, nil
}

// LifecycleStorage permits confined renewal lookup when such a directory is
// present and rejects every mutation.
type LifecycleStorage struct{ pkiDir string }

func (l *LifecycleStorage) MoveIssuedToExpired(string, *big.Int) error { return storage.ErrReadOnly }
func (l *LifecycleStorage) MoveIssuedToRenewed(string, *big.Int) error { return storage.ErrReadOnly }
func (l *LifecycleStorage) MoveIssuedToRevoked(string, *big.Int) error {
	return storage.ErrReadOnly
}
func (l *LifecycleStorage) MoveExpiredToRevoked(string, *big.Int) error {
	return storage.ErrReadOnly
}
func (l *LifecycleStorage) MoveRenewedToRevoked(string, *big.Int) error {
	return storage.ErrReadOnly
}
func (l *LifecycleStorage) GetExpiredCertificate(name string) ([]byte, error) {
	if err := storage.ValidateEntityName(name); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(l.pkiDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := readLegacyRegular(root, filepath.Join("expired", name+".crt"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, storage.ErrNotFound
	}
	return data, err
}

func (l *LifecycleStorage) ReplaceState(storage.LifecycleState) error { return storage.ErrReadOnly }

func (l *LifecycleStorage) GetRenewedCertificate(name string) ([]byte, error) {
	if err := storage.ValidateEntityName(name); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(l.pkiDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := readLegacyRegular(root, filepath.Join("renewed", "issued", name+".crt"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, storage.ErrNotFound
	}
	return data, err
}

var (
	_ storage.Backend          = (*Backend)(nil)
	_ storage.Components       = (*components)(nil)
	_ storage.ArtifactStorage  = (*ArtifactStorage)(nil)
	_ storage.LifecycleStorage = (*LifecycleStorage)(nil)
)

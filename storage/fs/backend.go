package fs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/gofrs/flock"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

// Backend is a transactional Easy-RSA filesystem backend.
type Backend struct {
	pkiDir string
	caName string
	mu     sync.RWMutex
}

// NewBackend constructs a filesystem backend without creating any files.
func NewBackend(pkiDir, caName string) *Backend {
	if caName == "" {
		caName = "ca"
	}
	return &Backend{pkiDir: pkiDir, caName: caName}
}

func (b *Backend) ReadOnly() bool { return false }

func (b *Backend) Empty() (bool, error) {
	rootPath, err := canonicalPKIPath(b.pkiDir)
	if err != nil {
		return false, err
	}
	pending, err := hasPendingTransactions(rootPath)
	if err != nil {
		return false, err
	}
	if pending {
		return false, fmt.Errorf("storage/fs: unfinished PKI transaction: %w", storage.ErrConflict)
	}
	return (OwnershipProbe{Dir: rootPath}).Empty()
}

func (b *Backend) Owned() (bool, error) {
	rootPath, err := canonicalPKIPath(b.pkiDir)
	if err != nil {
		return false, err
	}
	pending, err := hasPendingTransactions(rootPath)
	if err != nil {
		return false, err
	}
	if pending {
		return false, fmt.Errorf("storage/fs: unfinished PKI transaction: %w", storage.ErrConflict)
	}
	return (OwnershipProbe{Dir: rootPath}).Owned()
}

func (b *Backend) EnsureLayout() (err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	rootPath, err := canonicalPKIPath(b.pkiDir)
	if err != nil {
		return err
	}
	unlock, err := acquireBackendLock(rootPath, false)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if err := recoverTransactions(rootPath); err != nil {
		return err
	}
	if err := storage.ValidateOwnership(OwnershipProbe{Dir: rootPath}); err != nil {
		return err
	}
	complete, err := layoutComplete(rootPath)
	if err != nil {
		return err
	}
	if complete {
		return nil
	}
	shadow, err := newShadow(rootPath, true)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(shadow.path)) }()
	if err := InitDirs(shadow.path); err != nil {
		return err
	}
	return commitShadow(rootPath, shadow)
}

func layoutComplete(pkiDir string) (bool, error) {
	for _, directory := range []string{"private", "issued", "reqs", "certs_by_serial"} {
		info, err := os.Lstat(filepath.Join(pkiDir, directory))
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("storage/fs: layout path is not a directory: %s", directory)
		}
	}
	return true, nil
}

func (b *Backend) Initialize(reset bool) (err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	rootPath, err := canonicalPKIPath(b.pkiDir)
	if err != nil {
		return err
	}
	unlock, err := acquireBackendLock(rootPath, false)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if err := recoverTransactions(rootPath); err != nil {
		return err
	}

	probe := OwnershipProbe{Dir: rootPath}
	empty, err := probe.Empty()
	if err != nil {
		return err
	}
	if !empty {
		owned, ownedErr := probe.Owned()
		if ownedErr != nil {
			return ownedErr
		}
		if !owned {
			return storage.ErrForeignStorage
		}
		if !reset {
			return storage.ErrConflict
		}
	}

	shadow, err := newShadow(rootPath, false)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(shadow.path)) }()
	if err := InitDirs(shadow.path); err != nil {
		return err
	}
	return commitShadow(rootPath, shadow)
}

func (b *Backend) View(fn func(storage.Components) error) (err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	rootPath, err := canonicalPKIPath(b.pkiDir)
	if err != nil {
		return err
	}
	unlock, err := acquireBackendLock(rootPath, true)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()

	pending, err := hasPendingTransactions(rootPath)
	if err != nil {
		return err
	}
	if pending {
		return fmt.Errorf("storage/fs: unfinished PKI transaction: %w", storage.ErrConflict)
	}
	if err := storage.ValidateOwnership(OwnershipProbe{Dir: rootPath}); err != nil {
		return err
	}
	if empty, emptyErr := (OwnershipProbe{Dir: rootPath}).Empty(); emptyErr != nil {
		return emptyErr
	} else if !empty {
		if _, err := scanTree(rootPath, "", false); err != nil {
			return err
		}
	}
	return fn(storage.ReadOnlyComponents(newComponents(rootPath, b.caName)))
}

func (b *Backend) Update(fn func(storage.Components) error) (err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	rootPath, err := canonicalPKIPath(b.pkiDir)
	if err != nil {
		return err
	}
	unlock, err := acquireBackendLock(rootPath, false)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if err := recoverTransactions(rootPath); err != nil {
		return err
	}

	if err := storage.ValidateOwnership(OwnershipProbe{Dir: rootPath}); err != nil {
		return err
	}
	shadow, err := newShadow(rootPath, true)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(shadow.path)) }()

	if err := fn(newComponents(shadow.path, b.caName)); err != nil {
		return err
	}
	return commitShadow(rootPath, shadow)
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

func newComponents(pkiDir, caName string) *components {
	return &components{
		keys:      NewKeyStorage(pkiDir, caName),
		csrs:      NewCSRStorage(pkiDir),
		index:     NewIndexDB(pkiDir),
		serials:   NewSerialProvider(pkiDir),
		crls:      NewCRLHolder(pkiDir),
		artifacts: NewArtifactStorage(pkiDir),
		lifecycle: NewLifecycleStorage(pkiDir),
	}
}

func (c *components) Keys() storage.KeyStorage            { return c.keys }
func (c *components) CSRs() storage.CSRStorage            { return c.csrs }
func (c *components) Index() storage.IndexDB              { return c.index }
func (c *components) Serials() storage.SerialProvider     { return c.serials }
func (c *components) CRLs() storage.CRLHolder             { return c.crls }
func (c *components) Artifacts() storage.ArtifactStorage  { return c.artifacts }
func (c *components) Lifecycle() storage.LifecycleStorage { return c.lifecycle }

var processBackendLocks sync.Map

func processBackendLock(pkiDir string) *sync.RWMutex {
	lock, _ := processBackendLocks.LoadOrStore(pkiDir, &sync.RWMutex{})
	return lock.(*sync.RWMutex)
}

func acquireBackendLock(pkiDir string, shared bool) (func() error, error) {
	processLock := processBackendLock(pkiDir)
	var processLocked bool
	if shared {
		processLocked = processLock.TryRLock()
	} else {
		processLocked = processLock.TryLock()
	}
	if !processLocked {
		return nil, fmt.Errorf("storage/fs: PKI transaction: %w", storage.ErrConflict)
	}
	unlockProcess := func() {
		if shared {
			processLock.RUnlock()
		} else {
			processLock.Unlock()
		}
	}

	parent := filepath.Dir(pkiDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		unlockProcess()
		return nil, fmt.Errorf("storage/fs: create PKI parent: %w", err)
	}
	lockPath := filepath.Join(parent, "."+filepath.Base(pkiDir)+".go-easyrsa.lock")
	fileLock := flock.New(lockPath)
	var (
		locked bool
		err    error
	)
	if shared {
		locked, err = fileLock.TryRLock()
	} else {
		locked, err = fileLock.TryLock()
	}
	if err != nil {
		unlockProcess()
		return nil, fmt.Errorf("storage/fs: lock PKI: %w", err)
	}
	if !locked {
		unlockProcess()
		return nil, fmt.Errorf("storage/fs: PKI transaction: %w", storage.ErrConflict)
	}
	return func() error {
		err := fileLock.Unlock()
		unlockProcess()
		return err
	}, nil
}

func canonicalPKIPath(pkiDir string) (string, error) {
	absolute, err := filepath.Abs(pkiDir)
	if err != nil {
		return "", fmt.Errorf("storage/fs: resolve PKI directory: %w", err)
	}
	current := filepath.Clean(absolute)
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("storage/fs: resolve PKI symlinks: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("storage/fs: no existing parent for PKI directory %s", absolute)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

var (
	_ storage.Backend            = (*Backend)(nil)
	_ storage.OwnershipValidator = (*Backend)(nil)
	_ storage.Components         = (*components)(nil)
)

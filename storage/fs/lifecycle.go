package fs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

// LifecycleStorage moves files between Easy-RSA lifecycle directories.
type LifecycleStorage struct{ pkiDir string }

func NewLifecycleStorage(pkiDir string) *LifecycleStorage {
	return &LifecycleStorage{pkiDir: pkiDir}
}

func (l *LifecycleStorage) MoveIssuedToExpired(name string, serial *big.Int) error {
	return l.withRoot(func(root *os.Root) error {
		if err := l.recordEntityName(root, name, serial); err != nil {
			return err
		}
		return l.move(root, []lifecycleFile{{source: filepath.Join("issued", name+".crt"), destination: filepath.Join("expired", name+".crt")}})
	})
}

func (l *LifecycleStorage) MoveIssuedToRenewed(name string, serial *big.Int) error {
	return l.withRoot(func(root *os.Root) error {
		if err := l.recordEntityName(root, name, serial); err != nil {
			return err
		}
		return l.move(root, []lifecycleFile{{source: filepath.Join("issued", name+".crt"), destination: filepath.Join("renewed", "issued", name+".crt")}})
	})
}

func (l *LifecycleStorage) MoveIssuedToRevoked(name string, serial *big.Int) error {
	return l.withRoot(func(root *os.Root) error {
		if err := l.recordEntityName(root, name, serial); err != nil {
			return err
		}
		hexSerial := storage.HexSerial(serial)
		if err := writeLifecycleRootFile(root, filepath.Join("certs_by_serial", hexSerial+".revoked-assets"), []byte("issued"), 0o600); err != nil {
			return err
		}
		return l.move(root, []lifecycleFile{
			{source: filepath.Join("issued", name+".crt"), destination: filepath.Join("revoked", "certs_by_serial", hexSerial+".crt")},
			{source: filepath.Join("private", name+".key"), destination: filepath.Join("revoked", "private_by_serial", hexSerial+".key"), optional: true},
			{source: filepath.Join("reqs", name+".req"), destination: filepath.Join("revoked", "reqs_by_serial", hexSerial+".req"), optional: true},
		})
	})
}

func (l *LifecycleStorage) MoveExpiredToRevoked(name string, serial *big.Int) error {
	return l.withRoot(func(root *os.Root) error {
		if err := l.recordEntityName(root, name, serial); err != nil {
			return err
		}
		return l.move(root, []lifecycleFile{{
			source:      filepath.Join("expired", name+".crt"),
			destination: filepath.Join("revoked", "certs_by_serial", storage.HexSerial(serial)+".crt"),
		}})
	})
}

func (l *LifecycleStorage) MoveRenewedToRevoked(name string, serial *big.Int) error {
	return l.withRoot(func(root *os.Root) error {
		if err := l.recordEntityName(root, name, serial); err != nil {
			return err
		}
		return l.move(root, []lifecycleFile{{
			source:      filepath.Join("renewed", "issued", name+".crt"),
			destination: filepath.Join("revoked", "certs_by_serial", storage.HexSerial(serial)+".crt"),
		}})
	})
}

func (l *LifecycleStorage) recordEntityName(root *os.Root, name string, serial *big.Int) error {
	if err := storage.ValidateEntityName(name); err != nil {
		return err
	}
	if err := storage.ValidateSerial(serial); err != nil {
		return err
	}
	return writeLifecycleRootFile(root, filepath.Join("certs_by_serial", storage.HexSerial(serial)+".name"), []byte(name), 0o600)
}

func (l *LifecycleStorage) GetExpiredCertificate(name string) ([]byte, error) {
	if err := storage.ValidateEntityName(name); err != nil {
		return nil, err
	}
	var result []byte
	err := l.withRoot(func(root *os.Root) error {
		var err error
		result, err = readLifecycleRootFile(root, filepath.Join("expired", name+".crt"))
		return err
	})
	return result, err
}

func (l *LifecycleStorage) GetRenewedCertificate(name string) ([]byte, error) {
	if err := storage.ValidateEntityName(name); err != nil {
		return nil, err
	}
	var result []byte
	err := l.withRoot(func(root *os.Root) error {
		var err error
		result, err = readLifecycleRootFile(root, filepath.Join("renewed", "issued", name+".crt"))
		return err
	})
	return result, err
}

func (l *LifecycleStorage) withRoot(fn func(*os.Root) error) (err error) {
	root, err := os.OpenRoot(l.pkiDir)
	if errors.Is(err, fs.ErrNotExist) {
		return storage.ErrNotFound
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	return fn(root)
}

type lifecycleFile struct {
	source      string
	destination string
	optional    bool
}

type stagedLifecycleFile struct {
	lifecycleFile
	sourceInfo      fs.FileInfo
	destinationInfo fs.FileInfo
}

func (l *LifecycleStorage) move(root *os.Root, requested []lifecycleFile) error {
	staged := make([]stagedLifecycleFile, 0, len(requested))
	rollbackDestinations := func() error {
		var rollbackErrors []error
		for i := len(staged) - 1; i >= 0; i-- {
			move := staged[i]
			current, statErr := root.Lstat(move.destination)
			if errors.Is(statErr, fs.ErrNotExist) {
				continue
			}
			if statErr != nil {
				rollbackErrors = append(rollbackErrors, statErr)
				continue
			}
			if !os.SameFile(move.destinationInfo, current) {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("storage/fs: lifecycle destination changed: %s", move.destination))
				continue
			}
			rollbackErrors = append(rollbackErrors, root.Remove(move.destination))
		}
		return errors.Join(rollbackErrors...)
	}

	for _, move := range requested {
		if _, statErr := root.Lstat(move.destination); statErr == nil {
			return errors.Join(storage.ErrConflict, rollbackDestinations())
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return errors.Join(statErr, rollbackDestinations())
		}
		sourceInfo, statErr := root.Lstat(move.source)
		if errors.Is(statErr, fs.ErrNotExist) && move.optional {
			continue
		}
		if errors.Is(statErr, fs.ErrNotExist) {
			return errors.Join(storage.ErrNotFound, rollbackDestinations())
		}
		if statErr != nil {
			return errors.Join(statErr, rollbackDestinations())
		}
		if !sourceInfo.Mode().IsRegular() {
			return errors.Join(fmt.Errorf("storage/fs: lifecycle source is not regular: %s", move.source), rollbackDestinations())
		}
		if err := root.MkdirAll(filepath.Dir(move.destination), 0o755); err != nil {
			return errors.Join(err, rollbackDestinations())
		}
		destinationInfo, copyErr := copyLifecycleRootFile(root, move.source, move.destination, sourceInfo)
		if copyErr != nil {
			return errors.Join(copyErr, rollbackDestinations())
		}
		staged = append(staged, stagedLifecycleFile{lifecycleFile: move, sourceInfo: sourceInfo, destinationInfo: destinationInfo})
	}

	for _, move := range staged {
		current, statErr := root.Lstat(move.source)
		if statErr != nil {
			return errors.Join(statErr, rollbackDestinations())
		}
		if !os.SameFile(move.sourceInfo, current) {
			return errors.Join(fmt.Errorf("storage/fs: lifecycle source changed: %s", move.source), rollbackDestinations())
		}
		if removeErr := root.Remove(move.source); removeErr != nil {
			return errors.Join(removeErr, rollbackDestinations())
		}
	}
	return nil
}

func copyLifecycleRootFile(root *os.Root, sourceName, destinationName string, expected fs.FileInfo) (destinationInfo fs.FileInfo, err error) {
	source, err := openRootRegular(root, sourceName)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	openedInfo, err := source.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(expected, openedInfo) {
		return nil, fmt.Errorf("storage/fs: lifecycle source changed while opening: %s", sourceName)
	}
	destination, err := root.OpenFile(destinationName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, openedInfo.Mode().Perm())
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, storage.ErrConflict
		}
		return nil, err
	}
	defer func() { err = errors.Join(err, destination.Close()) }()
	destinationInfo, err = destination.Stat()
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(destination, source); err != nil {
		return nil, err
	}
	if err := destination.Sync(); err != nil {
		return nil, err
	}
	return destinationInfo, nil
}

func readLifecycleRootFile(root *os.Root, name string) (data []byte, err error) {
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("storage/fs: lifecycle file is not regular: %s", name)
	}
	file, err := openRootRegular(root, name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("storage/fs: lifecycle file changed while opening: %s", name)
	}
	return io.ReadAll(file)
}

func writeLifecycleRootFile(root *os.Root, name string, data []byte, mode fs.FileMode) error {
	if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return err
	}
	return root.WriteFile(name, data, mode)
}

// readLifecycleFile is retained for non-lifecycle facets. Backend views and
// updates use private snapshots, while lifecycle methods above stay rooted.
func readLifecycleFile(name string) (data []byte, err error) {
	info, err := os.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("storage/fs: lifecycle file is not regular: %s", name)
	}
	file, err := openRegularFile(name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("storage/fs: lifecycle file changed while opening: %s", name)
	}
	return io.ReadAll(file)
}

var _ storage.LifecycleStorage = (*LifecycleStorage)(nil)

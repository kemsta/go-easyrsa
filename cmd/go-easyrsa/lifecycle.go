package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofrs/flock"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

type lifecycleMove struct {
	source         string
	destination    string
	optional       bool
	expectedSource fs.FileInfo
}

type stagedLifecycleMove struct {
	lifecycleMove
	sourceInfo      fs.FileInfo
	destinationInfo fs.FileInfo
}

type lifecycleSession struct {
	root *os.Root
	lock *flock.Flock
}

type stagedPKIMoves struct {
	session *lifecycleSession
	moves   []stagedLifecycleMove
}

type regularPKIFile struct {
	data []byte
	info fs.FileInfo
}

func validateLifecycleName(name string) error {
	if name == "" {
		return errors.New("go-easyrsa: entity name must not be empty")
	}
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") || name == "." || strings.ContainsRune(name, 0) {
		return fmt.Errorf("go-easyrsa: invalid entity name %q", name)
	}
	return nil
}

func withLifecycleSession(pkiDir string, fn func(*lifecycleSession) error) (err error) {
	session, err := openLifecycleSession(pkiDir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, session.Close()) }()
	return fn(session)
}

func openLifecycleSession(pkiDir string) (*lifecycleSession, error) {
	rootPath, err := canonicalPKIPath(pkiDir)
	if err != nil {
		return nil, err
	}
	fileLock, err := acquirePKIMutationLock(rootPath)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		_ = fileLock.Unlock()
		return nil, fmt.Errorf("go-easyrsa: open PKI directory: %w", err)
	}
	indexInfo, err := root.Lstat("index.txt")
	if err != nil || !indexInfo.Mode().IsRegular() {
		_ = root.Close()
		_ = fileLock.Unlock()
		if err == nil {
			err = errors.New("index.txt is not a regular file")
		}
		return nil, fmt.Errorf("go-easyrsa: PKI ownership check failed: %w", err)
	}
	return &lifecycleSession{root: root, lock: fileLock}, nil
}

func withPKIMutationLock(pkiDir string, fn func() error) (err error) {
	rootPath, err := canonicalPKIPath(pkiDir)
	if err != nil {
		return err
	}
	fileLock, err := acquirePKIMutationLock(rootPath)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, fileLock.Unlock()) }()
	return fn()
}

func acquirePKIMutationLock(pkiDir string) (*flock.Flock, error) {
	rootPath, err := canonicalPKIPath(pkiDir)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(rootPath)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("go-easyrsa: create PKI parent directory: %w", err)
	}
	lockName := "." + filepath.Base(rootPath) + ".go-easyrsa.lock"
	fileLock := flock.New(filepath.Join(parent, lockName))
	locked, err := fileLock.TryLock()
	if err != nil {
		return nil, fmt.Errorf("go-easyrsa: lock PKI mutation: %w", err)
	}
	if !locked {
		return nil, errors.New("go-easyrsa: another PKI mutation is in progress")
	}
	return fileLock, nil
}

func canonicalPKIPath(pkiDir string) (string, error) {
	absolute, err := filepath.Abs(pkiDir)
	if err != nil {
		return "", fmt.Errorf("go-easyrsa: resolve PKI directory: %w", err)
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
			return "", fmt.Errorf("go-easyrsa: resolve PKI symlinks: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("go-easyrsa: no existing parent for PKI directory %s", absolute)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func (s *lifecycleSession) Close() error {
	if s == nil {
		return nil
	}
	var errs []error
	if s.root != nil {
		errs = append(errs, s.root.Close())
		s.root = nil
	}
	if s.lock != nil {
		errs = append(errs, s.lock.Unlock())
		s.lock = nil
	}
	return errors.Join(errs...)
}

func movePKIFile(pkiDir, source, destination string) error {
	return withLifecycleSession(pkiDir, func(session *lifecycleSession) error {
		staged, err := session.stageMoves([]lifecycleMove{{source: source, destination: destination}})
		if err != nil {
			return err
		}
		return staged.Commit()
	})
}

func (s *lifecycleSession) readRegular(relativePath string) (regularPKIFile, error) {
	pathInfo, err := s.root.Lstat(relativePath)
	if err != nil {
		return regularPKIFile{}, fmt.Errorf("go-easyrsa: inspect %s: %w", relativePath, err)
	}
	if !pathInfo.Mode().IsRegular() {
		return regularPKIFile{}, fmt.Errorf("go-easyrsa: lifecycle source is not a regular file: %s", relativePath)
	}
	file, err := openLifecycleSource(s.root, relativePath)
	if err != nil {
		return regularPKIFile{}, fmt.Errorf("go-easyrsa: open %s: %w", relativePath, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return regularPKIFile{}, fmt.Errorf("go-easyrsa: stat opened source %s: %w", relativePath, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return regularPKIFile{}, fmt.Errorf("go-easyrsa: lifecycle source changed while opening: %s", relativePath)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return regularPKIFile{}, fmt.Errorf("go-easyrsa: read %s: %w", relativePath, err)
	}
	return regularPKIFile{data: data, info: openedInfo}, nil
}

func (s *lifecycleSession) stageIssuedCertificate(name string, serial *big.Int, certificateInfo fs.FileInfo) (*stagedPKIMoves, error) {
	if err := validateLifecycleName(name); err != nil {
		return nil, err
	}
	hexSerial := storage.HexSerial(serial)
	return s.stageMoves([]lifecycleMove{
		{
			source:         filepath.Join("issued", name+".crt"),
			destination:    filepath.Join("revoked", "certs_by_serial", hexSerial+".crt"),
			expectedSource: certificateInfo,
		},
		{
			source:      filepath.Join("private", name+".key"),
			destination: filepath.Join("revoked", "private_by_serial", hexSerial+".key"),
			optional:    true,
		},
		{
			source:      filepath.Join("reqs", name+".req"),
			destination: filepath.Join("revoked", "reqs_by_serial", hexSerial+".req"),
			optional:    true,
		},
	})
}

func (s *lifecycleSession) stageExpiredCertificate(name string, serial *big.Int, certificateInfo fs.FileInfo) (*stagedPKIMoves, error) {
	if err := validateLifecycleName(name); err != nil {
		return nil, err
	}
	return s.stageMoves([]lifecycleMove{{
		source:         filepath.Join("expired", name+".crt"),
		destination:    filepath.Join("revoked", "certs_by_serial", storage.HexSerial(serial)+".crt"),
		expectedSource: certificateInfo,
	}})
}

func (s *lifecycleSession) stageMoves(requested []lifecycleMove) (*stagedPKIMoves, error) {
	staged := &stagedPKIMoves{session: s}
	fail := func(err error) (*stagedPKIMoves, error) {
		return nil, errors.Join(err, staged.Rollback())
	}

	for _, move := range requested {
		if _, err := s.root.Lstat(move.destination); err == nil {
			return fail(fmt.Errorf("go-easyrsa: destination already exists: %s", move.destination))
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fail(fmt.Errorf("go-easyrsa: inspect lifecycle destination %s: %w", move.destination, err))
		}

		pathInfo, err := s.root.Lstat(move.source)
		if errors.Is(err, fs.ErrNotExist) && move.optional {
			continue
		}
		if err != nil {
			return fail(fmt.Errorf("go-easyrsa: inspect lifecycle source %s: %w", move.source, err))
		}
		if !pathInfo.Mode().IsRegular() {
			return fail(fmt.Errorf("go-easyrsa: lifecycle source is not a regular file: %s", move.source))
		}
		if move.expectedSource != nil && !os.SameFile(move.expectedSource, pathInfo) {
			return fail(fmt.Errorf("go-easyrsa: lifecycle source changed before staging: %s", move.source))
		}
		if err := s.root.MkdirAll(filepath.Dir(move.destination), 0o755); err != nil {
			return fail(fmt.Errorf("go-easyrsa: create lifecycle directory: %w", err))
		}

		source, err := openLifecycleSource(s.root, move.source)
		if err != nil {
			return fail(fmt.Errorf("go-easyrsa: open lifecycle source %s: %w", move.source, err))
		}
		openedInfo, err := source.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
			_ = source.Close()
			return fail(fmt.Errorf("go-easyrsa: lifecycle source changed while staging: %s", move.source))
		}
		destination, err := s.root.OpenFile(move.destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, openedInfo.Mode().Perm())
		if err != nil {
			_ = source.Close()
			return fail(fmt.Errorf("go-easyrsa: create lifecycle destination %s: %w", move.destination, err))
		}
		destinationInfo, statErr := destination.Stat()
		staged.moves = append(staged.moves, stagedLifecycleMove{
			lifecycleMove:   move,
			sourceInfo:      openedInfo,
			destinationInfo: destinationInfo,
		})
		_, copyErr := io.Copy(destination, source)
		closeSourceErr := source.Close()
		syncErr := destination.Sync()
		closeDestinationErr := destination.Close()
		if statErr != nil || copyErr != nil || closeSourceErr != nil || syncErr != nil || closeDestinationErr != nil {
			return fail(fmt.Errorf(
				"go-easyrsa: stage lifecycle move %s: %w",
				move.source,
				errors.Join(statErr, copyErr, closeSourceErr, syncErr, closeDestinationErr),
			))
		}
	}
	return staged, nil
}

func (s *stagedPKIMoves) Commit() error {
	var errs []error
	for _, move := range s.moves {
		destination, err := s.session.root.Lstat(move.destination)
		if err != nil {
			errs = append(errs, fmt.Errorf("inspect lifecycle destination %s before source removal: %w", move.destination, err))
			continue
		}
		if move.destinationInfo == nil || !os.SameFile(move.destinationInfo, destination) {
			errs = append(errs, fmt.Errorf("lifecycle destination changed before source removal: %s", move.destination))
			continue
		}
		current, err := s.session.root.Lstat(move.source)
		if err != nil {
			errs = append(errs, fmt.Errorf("inspect lifecycle source %s before removal: %w", move.source, err))
			continue
		}
		if !os.SameFile(move.sourceInfo, current) {
			errs = append(errs, fmt.Errorf("lifecycle source changed before removal: %s", move.source))
			continue
		}
		if err := s.session.root.Remove(move.source); err != nil {
			errs = append(errs, fmt.Errorf("remove lifecycle source %s: %w", move.source, err))
		}
	}
	return errors.Join(errs...)
}

func (s *stagedPKIMoves) Rollback() error {
	if s == nil || s.session == nil || s.session.root == nil {
		return nil
	}
	var errs []error
	for _, move := range s.moves {
		current, err := s.session.root.Lstat(move.destination)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("inspect staged destination %s: %w", move.destination, err))
			continue
		}
		if move.destinationInfo == nil || !os.SameFile(move.destinationInfo, current) {
			errs = append(errs, fmt.Errorf("staged destination changed before rollback: %s", move.destination))
			continue
		}
		if err := s.session.root.Remove(move.destination); err != nil {
			errs = append(errs, fmt.Errorf("remove staged destination %s: %w", move.destination, err))
		}
	}
	return errors.Join(errs...)
}

func removeRevokedExports(session *lifecycleSession, name string) error {
	if err := validateLifecycleName(name); err != nil {
		return err
	}
	var errs []error
	for _, relativePath := range []string{
		filepath.Join("private", name+".p12"),
		filepath.Join("private", name+".p8"),
		filepath.Join("private", name+".p1"),
		filepath.Join("issued", name+".p7b"),
	} {
		if err := session.root.Remove(relativePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", relativePath, err))
		}
	}
	return errors.Join(errs...)
}

package fs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

// ArtifactStorage persists generated artifacts beneath a PKI root.
type ArtifactStorage struct{ pkiDir string }

func NewArtifactStorage(pkiDir string) *ArtifactStorage {
	return &ArtifactStorage{pkiDir: pkiDir}
}

func (a *ArtifactStorage) PutArtifact(artifact storage.Artifact) error {
	if err := storage.ValidateArtifactPath(artifact.Path); err != nil {
		return err
	}
	if err := storage.ValidateArtifactVisibility(artifact.Visibility); err != nil {
		return err
	}
	mode := fs.FileMode(0o644)
	if artifact.Visibility == storage.ArtifactPrivate {
		mode = 0o600
	}
	name := filepath.Join(a.pkiDir, filepath.FromSlash(artifact.Path))
	if info, err := os.Lstat(name); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("storage/fs: artifact destination is not regular: %s", artifact.Path)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return writeAtomicMode(name, artifact.Data, mode)
}

func (a *ArtifactStorage) GetArtifact(name string) (artifact storage.Artifact, err error) {
	if err := storage.ValidateArtifactPath(name); err != nil {
		return storage.Artifact{}, err
	}
	fullPath := filepath.Join(a.pkiDir, filepath.FromSlash(name))
	info, err := os.Lstat(fullPath)
	if errors.Is(err, fs.ErrNotExist) {
		return storage.Artifact{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.Artifact{}, err
	}
	if !info.Mode().IsRegular() {
		return storage.Artifact{}, fmt.Errorf("storage/fs: artifact is not regular: %s", name)
	}
	file, err := openRegularFile(fullPath)
	if err != nil {
		return storage.Artifact{}, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	opened, err := file.Stat()
	if err != nil {
		return storage.Artifact{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return storage.Artifact{}, fmt.Errorf("storage/fs: artifact changed while opening: %s", name)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return storage.Artifact{}, err
	}
	visibility := storage.ArtifactPublic
	if opened.Mode().Perm()&0o077 == 0 {
		visibility = storage.ArtifactPrivate
	}
	return storage.Artifact{Path: name, Data: data, Visibility: visibility}, nil
}

func (a *ArtifactStorage) DeleteArtifact(name string) error {
	if err := storage.ValidateArtifactPath(name); err != nil {
		return err
	}
	fullPath := filepath.Join(a.pkiDir, filepath.FromSlash(name))
	info, err := os.Lstat(fullPath)
	if errors.Is(err, fs.ErrNotExist) {
		return storage.ErrNotFound
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("storage/fs: artifact is not regular: %s", name)
	}
	return os.Remove(fullPath)
}

func writeAtomicMode(name string, data []byte, mode fs.FileMode) (err error) {
	directory := filepath.Dir(name)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".artifact-tmp-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() {
		if temporary != nil {
			err = errors.Join(err, temporary.Close())
		}
		if temporaryName != "" {
			err = errors.Join(err, removeIfExists(temporaryName))
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		temporary = nil
		return err
	}
	temporary = nil
	if err := os.Rename(temporaryName, name); err != nil {
		return err
	}
	temporaryName = ""
	return syncDirectory(directory)
}

func removeIfExists(name string) error {
	err := os.Remove(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

var _ storage.ArtifactStorage = (*ArtifactStorage)(nil)

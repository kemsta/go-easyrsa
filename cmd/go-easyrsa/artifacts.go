package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func writePKIArtifact(pkiDir, relativePath string, data []byte, mode fs.FileMode) (string, error) {
	clean := filepath.Clean(relativePath)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("go-easyrsa: invalid artifact path %q", relativePath)
	}

	rootPath, err := filepath.Abs(pkiDir)
	if err != nil {
		return "", fmt.Errorf("go-easyrsa: resolve PKI directory: %w", err)
	}
	if err := os.MkdirAll(rootPath, 0o755); err != nil {
		return "", fmt.Errorf("go-easyrsa: create PKI directory: %w", err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return "", fmt.Errorf("go-easyrsa: open PKI directory: %w", err)
	}
	defer root.Close()

	dir := filepath.Dir(clean)
	if err := root.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("go-easyrsa: create artifact directory %q: %w", dir, err)
	}
	tmp, tmpName, err := createRootTemp(root, dir, filepath.Base(clean), mode)
	if err != nil {
		return "", err
	}
	defer root.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("go-easyrsa: write artifact %q: %w", clean, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("go-easyrsa: sync artifact %q: %w", clean, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("go-easyrsa: close artifact %q: %w", clean, err)
	}
	if err := root.Rename(tmpName, clean); err != nil {
		return "", fmt.Errorf("go-easyrsa: replace artifact %q: %w", clean, err)
	}
	return filepath.Join(rootPath, clean), nil
}

func createRootTemp(root *os.Root, dir, base string, mode fs.FileMode) (*os.File, string, error) {
	for range 100 {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("go-easyrsa: generate artifact temp name: %w", err)
		}
		name := filepath.Join(dir, "."+base+".tmp-"+hex.EncodeToString(random[:]))
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err == nil {
			if err := file.Chmod(mode); err != nil {
				_ = file.Close()
				_ = root.Remove(name)
				return nil, "", fmt.Errorf("go-easyrsa: set artifact permissions: %w", err)
			}
			return file, name, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", fmt.Errorf("go-easyrsa: create artifact temp file: %w", err)
		}
	}
	return nil, "", errors.New("go-easyrsa: could not allocate artifact temp file")
}

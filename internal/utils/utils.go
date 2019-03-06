package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func WriteFileAtomic(path string, r io.Reader, mode os.FileMode) error {
	dir, file := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	fd, err := os.CreateTemp(dir, file)
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}
	defer func() {
		_ = os.Remove(fd.Name())
	}()
	defer func(fd *os.File) {
		_ = fd.Close()
	}(fd)
	if _, err := io.Copy(fd, r); err != nil {
		return fmt.Errorf("cannot write data to tempfile %q: %w", fd.Name(), err)
	}
	if err := fd.Sync(); err != nil {
		return fmt.Errorf("can't flush tempfile %q: %w", fd.Name(), err)
	}
	if err := fd.Close(); err != nil {
		return fmt.Errorf("can't close tempfile %q: %w", fd.Name(), err)
	}
	if err := os.Chmod(fd.Name(), mode); err != nil {
		return fmt.Errorf("can't set filemode on tempfile %q: %w", fd.Name(), err)
	}
	if err := os.Rename(fd.Name(), path); err != nil {
		return fmt.Errorf("cannot replace %q with tempfile %q: %w", path, fd.Name(), err)
	}
	return nil
}

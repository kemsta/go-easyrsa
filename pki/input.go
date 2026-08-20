package pki

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

func readRegularPath(name string) (data []byte, regular bool, err error) {
	return readRegularPathWith(name, openPKIInput)
}

func readRegularPathWith(name string, opener func(string) (*os.File, error)) (data []byte, regular bool, err error) {
	pathInfo, err := os.Stat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, false, nil
	}
	// Force lazy Windows file IDs to be captured before the opener can race a
	// replacement into the path.
	_ = os.SameFile(pathInfo, pathInfo)
	file, err := opener(name)
	if err != nil {
		return nil, false, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return nil, false, fmt.Errorf("pki: input changed while opening: %s", name)
	}
	data, err = io.ReadAll(file)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func readRequiredRegularPath(name string) ([]byte, error) {
	data, regular, err := readRegularPath(name)
	if err != nil {
		return nil, err
	}
	if !regular {
		return nil, fmt.Errorf("pki: path is not a regular file: %s", name)
	}
	return data, nil
}

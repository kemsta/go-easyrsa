package pki

import (
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
)

type KeyStorage interface {
	Put(pair *X509Pair) error                       // Put new pair to storage. Overwrite if already exist.
	GetByCN(cn string) ([]*X509Pair, error)         // Get all keypairs by CN.
	GetBySerial(serial *big.Int) (*X509Pair, error) // Get one keypair by serial.
	DeleteByCn(cn string) error                     // Delete all keypairs by CN.
	DeleteBySerial(serial *big.Int) error           // Delete one keypair by serial.
}

type DirKeyStorage struct {
	keydir string
}

func NewDirKeyStorage(keydir string) (*DirKeyStorage, error) {
	if keydir == "" {
		return nil, errors.New("empty keydir")
	}
	if _, err := os.Stat(keydir); err != nil || !filepath.IsAbs(keydir) {
		return nil, errors.New("keydir is not exist or not abs")
	}
	return &DirKeyStorage{keydir: keydir}, nil
}

func (s *DirKeyStorage) Put(pair *X509Pair) error {
	certPath, keyPath, err := s.makePath(pair)
	if err != nil {
		return errors.Wrap(err, "can`t make path")
	}
	err = ioutil.WriteFile(certPath, pair.CertPemBytes, 0644)
	if err != nil {
		return errors.Wrap(err, "can`t write cert")
	}
	err = ioutil.WriteFile(keyPath, pair.KeyPemBytes, 0600)
	if err != nil {
		return errors.Wrap(err, "can`t write key")
	}
	return nil
}

func (s *DirKeyStorage) DeleteByCn(cn string) error {
	err := os.RemoveAll(filepath.Join(s.keydir, cn))
	if err != nil {
		return errors.Wrap(err, "can`t delete by cn")
	}
	return nil
}

func (s *DirKeyStorage) DeleteBySerial(serial *big.Int) error {
	panic("implement me")
}

func (*DirKeyStorage) GetByCN(cn string) ([]*X509Pair, error) {
	panic("implement me")
}

func (*DirKeyStorage) GetBySerial(serial *big.Int) (*X509Pair, error) {
	panic("implement me")
}

func (s *DirKeyStorage) makePath(pair *X509Pair) (certPath, keyPath string, err error) {
	if pair.CN == "" || pair.Serial == nil {
		return "", "", errors.New("empty cn or serial")
	}
	basePath := filepath.Join(s.keydir, pair.CN)
	err = os.MkdirAll(basePath, 0755)
	if err != nil {
		return "", "", errors.Wrap(err, "can`t create dir for key pair")
	}
	return filepath.Join(basePath, fmt.Sprintf("%s.crt", pair.Serial)),
		filepath.Join(basePath, fmt.Sprintf("%s.key", pair.Serial)), nil
}

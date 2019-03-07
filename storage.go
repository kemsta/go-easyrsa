package pki

import (
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
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
	err := os.Remove(filepath.Join(s.keydir, cn))
	if err != nil {
		return errors.Wrap(err, "can`t delete by cn")
	}
	return nil
}

func (s *DirKeyStorage) DeleteBySerial(serial *big.Int) error {
	pair, err := s.GetBySerial(serial)
	if err != nil {
		return errors.Wrap(err, "can`t find pair by serial")
	}
	certPath := filepath.Join(s.keydir, pair.CN, fmt.Sprintf("%s.crt", pair.Serial.Text(16)))
	keyPath := filepath.Join(s.keydir, pair.CN, fmt.Sprintf("%s.key", pair.Serial.Text(16)))
	err = os.RemoveAll(certPath)
	if err != nil {
		return errors.Wrap(err, "can`t delete cert")
	}
	err = os.RemoveAll(keyPath)
	if err != nil {
		return errors.Wrap(err, "can`t delete key")
	}
	return nil
}

func (s *DirKeyStorage) GetByCN(cn string) ([]*X509Pair, error) {
	res := make([]*X509Pair, 0)
	err := filepath.Walk(filepath.Join(s.keydir, cn), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) == ".crt" {
			fileName := filepath.Base(path)
			serial, err := strconv.ParseInt(fileName[0:len(fileName)-len(filepath.Ext(fileName))], 16, 64)
			if err != nil {
				return nil
			}
			certBytes, err := ioutil.ReadFile(path)
			if err != nil {
				return nil
			}
			keyBytes, err := ioutil.ReadFile(fmt.Sprintf("%s.key", path[0:len(path)-len(filepath.Ext(path))]))
			if err != nil {
				return nil
			}
			res = append(res, NewX509Pair(keyBytes, certBytes, cn, big.NewInt(serial)))
		}
		return nil
	})
	return res, err
}

func (s *DirKeyStorage) GetBySerial(serial *big.Int) (*X509Pair, error) {
	var res *X509Pair
	err := filepath.Walk(s.keydir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if filepath.Ext(path) == ".crt" {
			fileName := filepath.Base(path)
			ser, err := strconv.ParseInt(fileName[0:len(fileName)-len(filepath.Ext(fileName))], 16, 64)
			if err != nil {
				return nil
			}
			cn := filepath.Base(filepath.Dir(path))
			if serial.Text(16) == big.NewInt(ser).Text(16) {
				certBytes, err := ioutil.ReadFile(path)
				if err != nil {
					return nil
				}
				keyBytes, err := ioutil.ReadFile(fmt.Sprintf("%s.key", path[0:len(path)-len(filepath.Ext(path))]))
				if err != nil {
					return nil
				}
				res = NewX509Pair(keyBytes, certBytes, cn, big.NewInt(ser))
				return nil
			}
		}
		return nil
	})
	if res == nil {
		return nil, errors.New("can`t find by serial")
	}
	return res, err
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
	return filepath.Join(basePath, fmt.Sprintf("%s.crt", pair.Serial.Text(16))),
		filepath.Join(basePath, fmt.Sprintf("%s.key", pair.Serial.Text(16))), nil
}

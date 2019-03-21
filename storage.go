package easyrsa

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/gofrs/flock"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

type KeyStorage interface {
	Put(pair *X509Pair) error                       // Put new pair to Storage. Overwrite if already exist.
	GetByCN(cn string) ([]*X509Pair, error)         // Get all keypairs by CN.
	GetLastByCn(cn string) (*X509Pair, error)       // Get last pair by CN.
	GetBySerial(serial *big.Int) (*X509Pair, error) // Get one keypair by serial.
	DeleteByCn(cn string) error                     // Delete all keypairs by CN.
	DeleteBySerial(serial *big.Int) error           // Delete one keypair by serial.
	GetAll() ([]*X509Pair, error)                   // Get all keypair
}

type SerialProvider interface {
	Next() (*big.Int, error) // Next return next uniq serial
}

type CRLHolder interface {
	Put([]byte) error                    // Put file content for crl
	Get() (*pkix.CertificateList, error) // Get current revoked cert list
}

// FileCRLHolder implement CRLHolder interface
type FileCRLHolder struct {
	flock.Flock
	path string
}

func NewFileCRLHolder(path string) *FileCRLHolder {
	locker := *flock.New(path)
	return &FileCRLHolder{Flock: locker, path: path}
}

func (h *FileCRLHolder) Put(content []byte) error {
	ctx, _ := context.WithTimeout(context.Background(), time.Second*10)
	locked, err := h.TryLockContext(ctx, 1)
	if err != nil {
		return err
	}
	if !locked {
		return errors.New("can`t lock serial file")
	}
	defer func() {
		_ = h.Unlock()
	}()
	err = ioutil.WriteFile(h.path, content, 0666)
	if err != nil {
		return errors.Wrap(err, "can`t put new crl file")
	}
	return nil
}

func (h *FileCRLHolder) Get() (*pkix.CertificateList, error) {
	err := h.RLock()
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = h.Unlock()
	}()
	if stat, err := os.Stat(h.path); err != nil || stat.Size() == 0 {
		return &pkix.CertificateList{}, nil
	}
	bytes, err := ioutil.ReadFile(h.path)
	if err != nil {
		return nil, errors.Wrap(err, "can`t read crl")
	}
	list, err := x509.ParseCRL(bytes)
	if err != nil {
		return nil, errors.Wrap(err, "can`t parse crl")
	}
	return list, nil
}

// FileSerialProvider implement SerialProvider interface with storing serial in file
type FileSerialProvider struct {
	flock.Flock
	path string
}

func (p *FileSerialProvider) Next() (*big.Int, error) {
	ctx, _ := context.WithTimeout(context.Background(), time.Second*10)
	locked, err := p.TryLockContext(ctx, 1)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, errors.New("can`t lock serial file")
	}
	defer func() {
		_ = p.Unlock()
	}()
	res := big.NewInt(0)
	file, err := os.OpenFile(p.path, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return nil, errors.Wrap(err, "can`t open serial file")
	}
	defer func() {
		_ = file.Close()
	}()
	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, errors.Wrap(err, "can`t read serial file")
	}
	if len(bytes) != 0 {
		res.SetString(string(bytes), 16)
	}
	res.Add(big.NewInt(1), res)
	_ = file.Truncate(0)
	_, err = file.Seek(0, 0)
	if err != nil {
		return nil, errors.Wrap(err, "can`t write serial file")
	}
	_, err = file.Write([]byte(res.Text(16)))
	if err != nil {
		return nil, errors.Wrap(err, "can`t write serial file")
	}
	return res, nil
}

func NewFileSerialProvider(path string) *FileSerialProvider {
	locker := *flock.New(path)
	return &FileSerialProvider{
		Flock: locker,
		path:  path,
	}
}

// DirKeyStorage is a implementation KeyStorage interface with storing pairs on fs
type DirKeyStorage struct {
	keydir string
}

func NewDirKeyStorage(keydir string) *DirKeyStorage {
	return &DirKeyStorage{keydir: keydir}
}

// Put keypair in dir as /keydir/cn/serial.[crt,key]
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

// DeleteByCn delete all pair with cn
func (s *DirKeyStorage) DeleteByCn(cn string) error {
	err := os.Remove(filepath.Join(s.keydir, cn))
	if err != nil {
		return errors.Wrap(err, "can`t delete by cn")
	}
	return nil
}

// Delete only one pair with serial
func (s *DirKeyStorage) DeleteBySerial(serial *big.Int) error {
	pair, err := s.GetBySerial(serial)
	if err != nil {
		return errors.Wrap(err, "can`t find pair by serial")
	}
	certPath := filepath.Join(s.keydir, pair.CN, fmt.Sprintf("%s.crt", pair.Serial.Text(16)))
	keyPath := filepath.Join(s.keydir, pair.CN, fmt.Sprintf("%s.key", pair.Serial.Text(16)))
	err = os.Remove(certPath)
	if err != nil {
		return errors.Wrap(err, "can`t delete cert")
	}
	err = os.Remove(keyPath)
	if err != nil {
		return errors.Wrap(err, "can`t delete key")
	}
	return nil
}

// GetByCN return all pairs with cn
func (s *DirKeyStorage) GetByCN(cn string) ([]*X509Pair, error) {
	res := make([]*X509Pair, 0)
	err := filepath.Walk(filepath.Join(s.keydir, cn), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) == CertFileExtension {
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
	if len(res) == 0 {
		return nil, errors.WithStack(NewNotExist("not found"))
	}
	return res, err
}

// GetLastByCn return only last pair with cn
func (s *DirKeyStorage) GetLastByCn(cn string) (*X509Pair, error) {
	pairs, err := s.GetByCN(cn)
	if err != nil || len(pairs) == 0 {
		return nil, errors.Wrap(err, "can`t get cert")
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Serial.Cmp(pairs[j].Serial) == 1
	})
	return pairs[0], nil
}

// GetBySerial return only one pair with serial
func (s *DirKeyStorage) GetBySerial(serial *big.Int) (*X509Pair, error) {
	var res *X509Pair
	err := filepath.Walk(s.keydir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if filepath.Ext(path) == CertFileExtension {
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
		return nil, errors.WithStack(NewNotExist("not found"))
	}
	return res, err
}

// GetAll return all pairs
func (s *DirKeyStorage) GetAll() ([]*X509Pair, error) {
	res := make([]*X509Pair, 0)
	err := filepath.Walk(s.keydir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if filepath.Ext(path) == CertFileExtension {
			fileName := filepath.Base(path)
			ser, err := strconv.ParseInt(fileName[0:len(fileName)-len(filepath.Ext(fileName))], 16, 64)
			if err != nil {
				return nil
			}
			cn := filepath.Base(filepath.Dir(path))
			certBytes, err := ioutil.ReadFile(path)
			if err != nil {
				return nil
			}
			keyBytes, err := ioutil.ReadFile(fmt.Sprintf("%s.key", path[0:len(path)-len(filepath.Ext(path))]))
			if err != nil {
				return nil
			}
			res = append(res, NewX509Pair(keyBytes, certBytes, cn, big.NewInt(ser)))
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "can`t get all pairs")
	}
	return res, nil
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

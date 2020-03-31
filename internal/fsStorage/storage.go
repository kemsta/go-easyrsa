package fsStorage

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/gofrs/flock"
	"github.com/kemsta/go-easyrsa/pkg/pair"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

const (
	LockPeriod        = time.Millisecond * 100
	LockTimeout       = time.Second * 10
	CertFileExtension = ".crt" // certificate file extension
)

// Common CRLHolder implementation. It's saving file on fs
type FileCRLHolder struct {
	locker *flock.Flock
	path   string
}

func NewFileCRLHolder(path string) *FileCRLHolder {
	return &FileCRLHolder{locker: flock.New(fmt.Sprintf("%v.lock", path)), path: path}
}

// Save new crl content to storage
func (h *FileCRLHolder) Put(content []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), LockTimeout)
	defer cancel()
	locked, err := h.locker.TryLockContext(ctx, LockPeriod)
	if err != nil {
		return fmt.Errorf("there's error with saving cert to storage: %w", err)
	}
	if !locked {
		return fmt.Errorf("can`t lock serial file %v", h.path)
	}
	defer func() {
		_ = h.locker.Unlock()
	}()
	err = ioutil.WriteFile(h.path, content, 0666)
	if err != nil {
		return fmt.Errorf("can`t save new crl file %v: %w", h.path, err)
	}
	return nil
}

// Get crl content from storage
func (h *FileCRLHolder) Get() (*pkix.CertificateList, error) {
	err := h.locker.RLock()
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = h.locker.Unlock()
	}()
	if stat, err := os.Stat(h.path); err != nil || stat.Size() == 0 {
		return &pkix.CertificateList{}, nil
	}
	bytes, err := ioutil.ReadFile(h.path)
	if err != nil {
		return nil, fmt.Errorf("can`t read crl %v: %w", h.path, err)
	}
	list, err := x509.ParseCRL(bytes)
	if err != nil {
		return nil, fmt.Errorf("can`t parse crl \n %v: %w", string(bytes), err)
	}
	return list, nil
}

// FileSerialProvider implement SerialProvider interface with storing serial in file on fs
type FileSerialProvider struct {
	locker *flock.Flock
	path   string
}

// Get next serial and increment counter in storage
func (p *FileSerialProvider) Next() (*big.Int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), LockTimeout)
	defer cancel()
	locked, err := p.locker.TryLockContext(ctx, LockPeriod)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("can`t lock serial file %v", p.path)
	}
	defer func() {
		_ = p.locker.Unlock()
	}()
	res := big.NewInt(0)
	file, err := os.OpenFile(p.path, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return nil, fmt.Errorf("can`t open serial file %v: %w", p.path, err)
	}
	defer func() {
		_ = file.Close()
	}()
	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("can`t read serial file %v: %w", p.path, err)
	}
	if len(bytes) != 0 {
		res.SetString(string(bytes), 16)
	}
	res.Add(big.NewInt(1), res)
	_ = file.Truncate(0)
	_, err = file.Seek(0, 0)
	if err != nil {
		return nil, fmt.Errorf("can`t write serial file %v: %w", p.path, err)
	}
	_, err = file.Write([]byte(res.Text(16)))
	if err != nil {
		return nil, fmt.Errorf("can`t write serial file %v: %w", p.path, err)
	}
	return res, nil
}

func NewFileSerialProvider(path string) *FileSerialProvider {
	return &FileSerialProvider{
		locker: flock.New(fmt.Sprintf("%v.lock", path)),
		path:   path,
	}
}

// DirKeyStorage is a KeyStorage interface implementation with storing pairs on fs
type DirKeyStorage struct {
	keydir string
}

func NewDirKeyStorage(keydir string) *DirKeyStorage {
	return &DirKeyStorage{keydir: keydir}
}

// Put keypair in dir as /keydir/cn/serial.[crt,key]
func (s *DirKeyStorage) Put(pair *pair.X509Pair) error {
	certPath, keyPath, err := s.makePath(pair)
	if err != nil {
		return fmt.Errorf("can`t make path %v: %w", pair, err)
	}
	err = ioutil.WriteFile(certPath, pair.CertPemBytes, 0644)
	if err != nil {
		return fmt.Errorf("can`t write cert %v: %w", certPath, err)
	}
	err = ioutil.WriteFile(keyPath, pair.KeyPemBytes, 0600)
	if err != nil {
		return fmt.Errorf("can`t write key %v: %w", keyPath, err)
	}
	return nil
}

// DeleteByCn delete all pair with cn
func (s *DirKeyStorage) DeleteByCn(cn string) error {
	err := os.Remove(filepath.Join(s.keydir, cn))
	if err != nil {
		return fmt.Errorf("can`t delete by cn %v in %v: %w", cn, s.keydir, err)
	}
	return nil
}

// Delete only one pair with serial
func (s *DirKeyStorage) DeleteBySerial(serial *big.Int) error {
	p, err := s.GetBySerial(serial)
	if err != nil {
		return fmt.Errorf("can`t find pair by serial %v: %w", serial, err)
	}
	certPath := filepath.Join(s.keydir, p.CN, fmt.Sprintf("%s.crt", p.Serial.Text(16)))
	keyPath := filepath.Join(s.keydir, p.CN, fmt.Sprintf("%s.key", p.Serial.Text(16)))
	err = os.Remove(certPath)
	if err != nil {
		return fmt.Errorf("can`t delete cert %v: %w", certPath, err)
	}
	err = os.Remove(keyPath)
	if err != nil {
		return fmt.Errorf("can`t delete key %v: %w", keyPath, err)
	}
	return nil
}

// GetByCN return all pairs with cn
func (s *DirKeyStorage) GetByCN(cn string) ([]*pair.X509Pair, error) {
	res := make([]*pair.X509Pair, 0)
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
			res = append(res, pair.NewX509Pair(keyBytes, certBytes, cn, big.NewInt(serial)))
		}
		return nil
	})
	if len(res) == 0 {
		return nil, fmt.Errorf("%v not found", cn)
	}
	return res, err
}

// GetLastByCn return only last pair with cn
func (s *DirKeyStorage) GetLastByCn(cn string) (*pair.X509Pair, error) {
	pairs, err := s.GetByCN(cn)
	if err != nil || len(pairs) == 0 {
		return nil, fmt.Errorf("can`t get cert %v: %w", cn, err)
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Serial.Cmp(pairs[j].Serial) == 1
	})
	return pairs[0], nil
}

// GetBySerial return only one pair with serial
func (s *DirKeyStorage) GetBySerial(serial *big.Int) (*pair.X509Pair, error) {
	var res *pair.X509Pair
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
				res = pair.NewX509Pair(keyBytes, certBytes, cn, big.NewInt(ser))
				return nil
			}
		}
		return nil
	})
	if res == nil {
		return nil, fmt.Errorf("%v not found", serial)
	}
	return res, err
}

// GetAll return all pairs
func (s *DirKeyStorage) GetAll() ([]*pair.X509Pair, error) {
	res := make([]*pair.X509Pair, 0)
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
			res = append(res, pair.NewX509Pair(keyBytes, certBytes, cn, big.NewInt(ser)))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("can`t get all pairs: %w", err)
	}
	return res, nil
}

func (s *DirKeyStorage) makePath(pair *pair.X509Pair) (certPath, keyPath string, err error) {
	if pair.CN == "" || pair.Serial == nil {
		return "", "", errors.New("empty cn or serial")
	}
	basePath := filepath.Join(s.keydir, pair.CN)
	err = os.MkdirAll(basePath, 0755)
	if err != nil {
		return "", "", fmt.Errorf("can`t create dir for key pair %v: %w", pair, err)
	}
	return filepath.Join(basePath, fmt.Sprintf("%s.crt", pair.Serial.Text(16))),
		filepath.Join(basePath, fmt.Sprintf("%s.key", pair.Serial.Text(16))), nil
}

package fsStorage

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/gofrs/flock"
	"github.com/kemsta/go-easyrsa/pkg/pair"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	LockPeriod        = time.Millisecond * 100
	LockTimeout       = time.Second * 10
	CertFileExtension = ".crt" // certificate file extension
)

// FileCRLHolder is a common CRLHolder implementation. It's saving file on fs
type FileCRLHolder struct {
	locker *flock.Flock
	path   string
}

func NewFileCRLHolder(path string) *FileCRLHolder {
	return &FileCRLHolder{locker: flock.New(fmt.Sprintf("%v.lock", path)), path: path}
}

// Put the content fo crl to the storage
func (h *FileCRLHolder) Put(content []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), LockTimeout)
	defer cancel()
	locked, err := h.locker.TryLockContext(ctx, LockPeriod)
	if err != nil {
		return fmt.Errorf("there's error with saving crl to storage: %w", err)
	}
	if !locked {
		return fmt.Errorf("can`t lock serial file %v", h.path)
	}
	defer func() {
		_ = h.locker.Unlock()
	}()
	if err = writeFileAtomic(h.path, bytes.NewReader(content), 0644); err != nil {
		return fmt.Errorf("can't overwrite crl file %s with new content: %w", h.path, err)
	}

	return nil
}

// Get crl content from the storage
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
	fBytes, err := ioutil.ReadFile(h.path)
	if err != nil {
		return nil, fmt.Errorf("can`t read crl %v: %w", h.path, err)
	}
	list, err := x509.ParseCRL(fBytes)
	if err != nil {
		return nil, fmt.Errorf("can`t parse crl \n %v: %w", string(fBytes), err)
	}
	return list, nil
}

// FileSerialProvider implements SerialProvider interface with storing serial into the file on fs
type FileSerialProvider struct {
	locker *flock.Flock
	path   string
}

// Next serial and increment counter in storage
func (p *FileSerialProvider) Next() (*big.Int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), LockTimeout)
	defer cancel()
	locked, err := p.locker.TryLockContext(ctx, LockPeriod)
	if err != nil {
		return nil, fmt.Errorf("can`t lock serial file %v: %w", p.path, err)
	}
	if !locked {
		return nil, fmt.Errorf("can`t lock serial file %v", p.path)
	}
	defer func() {
		_ = p.locker.Unlock()
	}()
	res := big.NewInt(0)
	sBytes, err := ioutil.ReadFile(p.path)
	if os.IsNotExist(err) {
		// nothing to do. New serial
	} else if err != nil {
		return nil, fmt.Errorf("can`t read serial file %v: %w", p.path, err)
	}

	if len(sBytes) != 0 {
		res.SetString(string(sBytes), 16)
	}
	res.Add(big.NewInt(1), res)

	if err := writeFileAtomic(p.path, strings.NewReader(res.Text(16)), 0644); err != nil {
		return res, fmt.Errorf("can`t write cert %v: %w", p.path, err)
	}

	return res, nil
}

func NewFileSerialProvider(path string) *FileSerialProvider {
	return &FileSerialProvider{
		locker: flock.New(fmt.Sprintf("%v.lock", path)),
		path:   path,
	}
}

// DirKeyStorage is a storage interface implementation with storing pairs on fs
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
	if err := writeFileAtomic(certPath, bytes.NewReader(pair.CertPemBytes()), 0644); err != nil {
		return fmt.Errorf("can`t write cert %v: %w", certPath, err)
	}

	if err := writeFileAtomic(keyPath, bytes.NewReader(pair.KeyPemBytes()), 0644); err != nil {
		return fmt.Errorf("can`t write cert %v: %w", certPath, err)
	}
	return nil
}

// DeleteByCn delete all pairs by CN
func (s *DirKeyStorage) DeleteByCn(cn string) error {
	err := os.Remove(filepath.Join(s.keydir, cn))
	if err != nil {
		return fmt.Errorf("can`t delete by cn %v in %v: %w", cn, s.keydir, err)
	}
	return nil
}

// DeleteBySerial delete only one pair by serial
func (s *DirKeyStorage) DeleteBySerial(serial *big.Int) error {
	p, err := s.GetBySerial(serial)
	if err != nil {
		return fmt.Errorf("can`t find pair by serial %v: %w", serial, err)
	}
	certPath := filepath.Join(s.keydir, p.CN(), fmt.Sprintf("%s.crt", p.Serial().Text(16)))
	keyPath := filepath.Join(s.keydir, p.CN(), fmt.Sprintf("%s.key", p.Serial().Text(16)))
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

// GetByCN return all pairs by cn
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
			res = append(res, pair.ImportX509(keyBytes, certBytes, cn, big.NewInt(serial)))
		}
		return nil
	})
	if len(res) == 0 {
		return nil, fmt.Errorf("%v not found", cn)
	}
	return res, err
}

// GetLastByCn return only last pair by cn
func (s *DirKeyStorage) GetLastByCn(cn string) (*pair.X509Pair, error) {
	pairs, err := s.GetByCN(cn)
	if err != nil || len(pairs) == 0 {
		return nil, fmt.Errorf("can`t get cert %v: %w", cn, err)
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Serial().Cmp(pairs[j].Serial()) == 1
	})
	return pairs[0], nil
}

// GetBySerial return only one pair by serial
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
				res = pair.ImportX509(keyBytes, certBytes, cn, big.NewInt(ser))
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
			res = append(res, pair.ImportX509(keyBytes, certBytes, cn, big.NewInt(ser)))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("can`t get all pairs: %w", err)
	}
	return res, nil
}

func (s *DirKeyStorage) makePath(pair *pair.X509Pair) (certPath, keyPath string, err error) {
	if pair.CN() == "" || pair.Serial() == nil {
		return "", "", errors.New("empty cn or serial")
	}
	basePath := filepath.Join(s.keydir, pair.CN())
	err = os.MkdirAll(basePath, 0755)
	if err != nil {
		return "", "", fmt.Errorf("can`t create dir for key pair %v: %w", pair, err)
	}
	return filepath.Join(basePath, fmt.Sprintf("%s.crt", pair.Serial().Text(16))),
		filepath.Join(basePath, fmt.Sprintf("%s.key", pair.Serial().Text(16))), nil
}

func writeFileAtomic(path string, r io.Reader, mode os.FileMode) error {
	dir, file := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	fd, err := ioutil.TempFile(dir, file)
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
		return fmt.Errorf("can't flush tempfile %q: %v", fd.Name(), err)
	}
	if err := fd.Close(); err != nil {
		return fmt.Errorf("can't close tempfile %q: %v", fd.Name(), err)
	}
	if err := os.Chmod(fd.Name(), mode); err != nil {
		return fmt.Errorf("can't set filemode on tempfile %q: %w", fd.Name(), err)
	}
	if err := os.Rename(fd.Name(), path); err != nil {
		return fmt.Errorf("cannot replace %q with tempfile %q: %w", path, fd.Name(), err)
	}
	return nil
}

package compilantStorage

import (
	"bytes"
	"fmt"
	"github.com/kemsta/go-easyrsa/internal/utils"
	"github.com/kemsta/go-easyrsa/pkg/pair"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	LockPeriod        = time.Millisecond * 100
	LockTimeout       = time.Second * 10
	CertFileExtension = ".crt" // certificate file extension
)

//DirKeyStorage is easyrsa v3 compilant storage. It can be used as a drop-off replacement on the created with easyrsa v3 pki
type DirKeyStorage struct {
	pkidir string
}

func NewDirKeyStorage(pkidir string) *DirKeyStorage {
	return &DirKeyStorage{pkidir: pkidir}
}

func (s *DirKeyStorage) initDir() error {
	var once sync.Once
	var err error
	once.Do(func() {
		for _, dir := range []string{
			s.pkidir,
			filepath.Join(s.pkidir, "certs_by_serial"),
			filepath.Join(s.pkidir, "issued"),
			filepath.Join(s.pkidir, "private"),
			filepath.Join(s.pkidir, "reqs"),
			filepath.Join(s.pkidir, "revoked"),
			filepath.Join(s.pkidir, "revoked", "certs_by_serial"),
			filepath.Join(s.pkidir, "revoked", "private_by_serial"),
			filepath.Join(s.pkidir, "revoked", "reqs_by_serial"),
		} {
			err = os.MkdirAll(dir, 0750)
		}
	})
	return err
}

func (s *DirKeyStorage) Put(pair *pair.X509Pair) error {
	err := s.initDir()
	if err != nil {
		return fmt.Errorf("can`t make pki paths in %s: %w", s.pkidir, err)
	}

	var certPath, keyPath, serialPath string

	_, err = os.Stat(certPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("%s already exist. Abort writing to avoid overwriting this file", certPath)
		}
	}

	certPath = filepath.Join(s.pkidir, "issued", fmt.Sprintf("%s.crt", pair.CN()))
	keyPath = filepath.Join(s.pkidir, "private", fmt.Sprintf("%s.key", pair.CN()))
	serialPath = filepath.Join(s.pkidir, "certs_by_serial", fmt.Sprintf("%s.crt", strings.ToUpper(pair.Serial().Text(16))))
	if pair.CN() == "ca" {
		certPath = filepath.Join(s.pkidir, "ca.crt")
	}
	if err := utils.WriteFileAtomic(certPath, bytes.NewReader(pair.CertPemBytes()), 0644); err != nil {
		return fmt.Errorf("can`t write cert %v: %w", certPath, err)
	}
	if err := utils.WriteFileAtomic(serialPath, bytes.NewReader(pair.CertPemBytes()), 0644); err != nil {
		return fmt.Errorf("can`t write cert %v: %w", certPath, err)
	}

	if err := utils.WriteFileAtomic(keyPath, bytes.NewReader(pair.KeyPemBytes()), 0644); err != nil {
		return fmt.Errorf("can`t write key %v: %w", keyPath, err)
	}
	return nil
}

func (s *DirKeyStorage) GetByCN(cn string) ([]*pair.X509Pair, error) {
	res := make([]*pair.X509Pair, 0)
	certBytes, err := ioutil.ReadFile(filepath.Join(s.pkidir, "issued", fmt.Sprintf("%s.crt", cn)))
	if err != nil {
		return nil, fmt.Errorf("can't read cert by cn %s: %w", cn, err)
	}
	keyBytes, err := ioutil.ReadFile(filepath.Join(s.pkidir, "private", fmt.Sprintf("%s.key", cn)))
	if err != nil {
		return nil, fmt.Errorf("can't read key by cn %s: %w", cn, err)
	}
	res = append(res, pair.ImportX509(keyBytes, certBytes, cn, big.NewInt(0)))
	return res, err
}

func (s *DirKeyStorage) GetLastByCn(cn string) (*pair.X509Pair, error) {
	//TODO implement me
	panic("implement me")
}

func (s *DirKeyStorage) GetBySerial(serial *big.Int) (*pair.X509Pair, error) {
	//TODO implement me
	panic("implement me")
}

func (s *DirKeyStorage) DeleteByCN(cn string) error {
	//TODO implement me
	panic("implement me")
}

func (s *DirKeyStorage) DeleteBySerial(serial *big.Int) error {
	//TODO implement me
	panic("implement me")
}

func (s *DirKeyStorage) GetAll() ([]*pair.X509Pair, error) {
	//TODO implement me
	panic("implement me")
}

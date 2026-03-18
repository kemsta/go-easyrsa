// Package fs provides filesystem-backed implementations of all storage interfaces,
// using the easy-rsa-compatible PKI directory layout.
package fs

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/kemsta/go-easyrsa/cert"
	"github.com/kemsta/go-easyrsa/storage"
)

// InitDirs creates the required subdirectory structure under pkiDir.
func InitDirs(pkiDir string) error {
	for _, sub := range []string{"private", "issued", "reqs", "certs_by_serial"} {
		if err := os.MkdirAll(fsJoin(pkiDir, sub), 0755); err != nil {
			return err
		}
	}
	return nil
}

// fsJoin joins path components using the OS separator.
func fsJoin(elem ...string) string { return filepath.Join(elem...) }

// writeFile writes data to path, creating parent directories as needed.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// hexSerial returns n as an uppercase, even-length hex string (e.g. 1 → "01").
func hexSerial(n *big.Int) string {
	h := strings.ToUpper(n.Text(16))
	if len(h)%2 != 0 {
		h = "0" + h
	}
	return h
}

// --- KeyStorage ---

// KeyStorage implements storage.KeyStorage on the filesystem.
type KeyStorage struct {
	pkiDir string
	caName string
}

// NewKeyStorage creates a KeyStorage rooted at pkiDir.
// caName is the name of the CA entry (default "ca").
func NewKeyStorage(pkiDir, caName string) *KeyStorage {
	if caName == "" {
		caName = "ca"
	}
	return &KeyStorage{pkiDir: pkiDir, caName: caName}
}

func (ks *KeyStorage) certPath(name string) string {
	if name == ks.caName {
		return fsJoin(ks.pkiDir, "ca.crt")
	}
	return fsJoin(ks.pkiDir, "issued", name+".crt")
}

func (ks *KeyStorage) keyPath(name string) string {
	return fsJoin(ks.pkiDir, "private", name+".key")
}

func (ks *KeyStorage) serialPath(serial *big.Int) string {
	return fsJoin(ks.pkiDir, "certs_by_serial", hexSerial(serial)+".pem")
}

func (ks *KeyStorage) Put(pair *cert.Pair) error {
	if pair.CertPEM != nil {
		if err := writeFile(ks.certPath(pair.Name), pair.CertPEM); err != nil {
			return err
		}
		if serial, err := pair.Serial(); err == nil {
			if err := writeFile(ks.serialPath(serial), pair.CertPEM); err != nil {
				return err
			}
		}
	}
	if pair.KeyPEM != nil {
		if err := writeFile(ks.keyPath(pair.Name), pair.KeyPEM); err != nil {
			return err
		}
	}
	return nil
}

func (ks *KeyStorage) GetLastByName(name string) (*cert.Pair, error) {
	certPEM, err := os.ReadFile(ks.certPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	pair := &cert.Pair{Name: name, CertPEM: certPEM}
	if keyPEM, err := os.ReadFile(ks.keyPath(name)); err == nil {
		pair.KeyPEM = keyPEM
	}
	return pair, nil
}

func (ks *KeyStorage) GetByName(name string) ([]*cert.Pair, error) {
	pair, err := ks.GetLastByName(name)
	if err != nil {
		return nil, err
	}
	return []*cert.Pair{pair}, nil
}

func (ks *KeyStorage) GetBySerial(serial *big.Int) (*cert.Pair, error) {
	certPEM, err := os.ReadFile(ks.serialPath(serial))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, storage.ErrNotFound
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	name := c.Subject.CommonName
	pair := &cert.Pair{Name: name, CertPEM: certPEM}
	if keyPEM, err := os.ReadFile(ks.keyPath(name)); err == nil {
		pair.KeyPEM = keyPEM
	}
	return pair, nil
}

func (ks *KeyStorage) DeleteByName(name string) error {
	pair, err := ks.GetLastByName(name)
	if err != nil {
		return err
	}
	if serial, err := pair.Serial(); err == nil {
		_ = os.Remove(ks.serialPath(serial))
	}
	_ = os.Remove(ks.certPath(name))
	_ = os.Remove(ks.keyPath(name))
	return nil
}

func (ks *KeyStorage) DeleteBySerial(serial *big.Int) error {
	if err := os.Remove(ks.serialPath(serial)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (ks *KeyStorage) GetAll() ([]*cert.Pair, error) {
	var pairs []*cert.Pair

	if caPair, err := ks.GetLastByName(ks.caName); err == nil {
		pairs = append(pairs, caPair)
	}

	issuedDir := fsJoin(ks.pkiDir, "issued")
	entries, err := os.ReadDir(issuedDir)
	if err != nil {
		if os.IsNotExist(err) {
			return pairs, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".crt") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".crt")
		if pair, err := ks.GetLastByName(name); err == nil {
			pairs = append(pairs, pair)
		}
	}
	return pairs, nil
}

// --- CSRStorage ---

// CSRStorage implements storage.CSRStorage on the filesystem.
type CSRStorage struct {
	pkiDir string
}

// NewCSRStorage creates a CSRStorage rooted at pkiDir.
func NewCSRStorage(pkiDir string) *CSRStorage {
	return &CSRStorage{pkiDir: pkiDir}
}

func (cs *CSRStorage) reqPath(name string) string {
	return fsJoin(cs.pkiDir, "reqs", name+".req")
}

func (cs *CSRStorage) PutCSR(name string, csrPEM []byte) error {
	return writeFile(cs.reqPath(name), csrPEM)
}

func (cs *CSRStorage) GetCSR(name string) ([]byte, error) {
	data, err := os.ReadFile(cs.reqPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return data, nil
}

func (cs *CSRStorage) DeleteCSR(name string) error {
	err := os.Remove(cs.reqPath(name))
	if err != nil && os.IsNotExist(err) {
		return storage.ErrNotFound
	}
	return err
}

func (cs *CSRStorage) ListCSRs() ([]string, error) {
	entries, err := os.ReadDir(fsJoin(cs.pkiDir, "reqs"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".req") {
			names = append(names, strings.TrimSuffix(e.Name(), ".req"))
		}
	}
	return names, nil
}

// --- SerialProvider ---

// SerialProvider implements storage.SerialProvider using a serial file.
type SerialProvider struct {
	path string
}

// NewSerialProvider creates a SerialProvider backed by pkiDir/serial.
func NewSerialProvider(pkiDir string) *SerialProvider {
	return &SerialProvider{path: fsJoin(pkiDir, "serial")}
}

func (sp *SerialProvider) Next() (*big.Int, error) {
	data, err := os.ReadFile(sp.path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		data = []byte("01\n")
	}

	hexStr := strings.TrimSpace(string(data))
	n := new(big.Int)
	n.SetString(hexStr, 16)

	next := new(big.Int).Add(n, big.NewInt(1))
	nextHex := hexSerial(next)
	if err := os.WriteFile(sp.path, []byte(nextHex+"\n"), 0644); err != nil {
		return nil, err
	}
	return n, nil
}

// --- CRLHolder ---

// CRLHolder implements storage.CRLHolder using a crl.pem file.
type CRLHolder struct {
	path string
}

// NewCRLHolder creates a CRLHolder backed by pkiDir/crl.pem.
func NewCRLHolder(pkiDir string) *CRLHolder {
	return &CRLHolder{path: fsJoin(pkiDir, "crl.pem")}
}

func (ch *CRLHolder) Put(pemBytes []byte) error {
	return os.WriteFile(ch.path, pemBytes, 0644)
}

func (ch *CRLHolder) Get() (*x509.RevocationList, error) {
	data, err := os.ReadFile(ch.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &x509.RevocationList{}, nil
		}
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return &x509.RevocationList{}, nil
	}
	return x509.ParseRevocationList(block.Bytes)
}

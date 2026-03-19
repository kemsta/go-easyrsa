// Package fs provides filesystem-backed implementations of all storage interfaces,
// using the easy-rsa-compatible PKI directory layout.
package fs

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"

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

// writeFile writes data to path atomically, creating parent directories as needed.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return writeAtomic(path, data)
}

// hexSerial is a package-local alias for storage.HexSerial.
func hexSerial(n *big.Int) string { return storage.HexSerial(n) }

// --- KeyStorage ---

// KeyStorage implements storage.KeyStorage on the filesystem.
// mu serializes all multi-step read and write operations within a process.
// Concurrent access from separate processes sharing the same pkiDir is not safe.
type KeyStorage struct {
	pkiDir string
	caName string
	mu     sync.RWMutex
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

func (ks *KeyStorage) nameSidecarPath(serial *big.Int) string {
	return fsJoin(ks.pkiDir, "certs_by_serial", hexSerial(serial)+".name")
}

func (ks *KeyStorage) Put(pair *cert.Pair) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if pair.CertPEM != nil {
		if err := writeFile(ks.certPath(pair.Name), pair.CertPEM); err != nil {
			return err
		}
		if serial, err := pair.Serial(); err == nil {
			if err := writeFile(ks.serialPath(serial), pair.CertPEM); err != nil {
				return err
			}
			// Store the storage entity name alongside the serial-indexed cert
			// so GetBySerial can return the correct name even when CN != name.
			if err := writeFile(ks.nameSidecarPath(serial), []byte(pair.Name)); err != nil {
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
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.getLastByNameLocked(name)
}

// getLastByNameLocked is the lock-free implementation called by GetLastByName
// and DeleteByName (which already hold the appropriate lock).
func (ks *KeyStorage) getLastByNameLocked(name string) (*cert.Pair, error) {
	certPEM, err := os.ReadFile(ks.certPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return ks.getFromRevoked(name)
		}
		return nil, err
	}
	pair := &cert.Pair{Name: name, CertPEM: certPEM}
	if keyPEM, err := os.ReadFile(ks.keyPath(name)); err == nil {
		pair.KeyPEM = keyPEM
	}
	return pair, nil
}

// getFromRevoked searches revoked/certs_by_serial/ for a cert matching name (CN).
// easy-rsa moves certs there when revoking.
func (ks *KeyStorage) getFromRevoked(name string) (*cert.Pair, error) {
	revokedDir := fsJoin(ks.pkiDir, "revoked", "certs_by_serial")
	entries, err := os.ReadDir(revokedDir)
	if err != nil {
		return nil, storage.ErrNotFound
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".crt") {
			continue
		}
		data, err := os.ReadFile(fsJoin(revokedDir, e.Name()))
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil || c.Subject.CommonName != name {
			continue
		}
		pair := &cert.Pair{Name: name, CertPEM: data}
		serialHex := strings.TrimSuffix(e.Name(), ".crt")
		keyPath := fsJoin(ks.pkiDir, "revoked", "private_by_serial", serialHex+".key")
		if keyPEM, err := os.ReadFile(keyPath); err == nil {
			pair.KeyPEM = keyPEM
		}
		return pair, nil
	}
	return nil, storage.ErrNotFound
}

func (ks *KeyStorage) GetByName(name string) ([]*cert.Pair, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	pair, err := ks.getLastByNameLocked(name)
	if err != nil {
		return nil, err
	}
	return []*cert.Pair{pair}, nil
}

func (ks *KeyStorage) GetBySerial(serial *big.Int) (*cert.Pair, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
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
	// Prefer the sidecar name file written by Put so that the storage key
	// (entity name) is returned instead of the Subject CN, which may differ
	// in org mode when WithSubjectOverride sets a custom CN.
	name := c.Subject.CommonName
	hexStr := hexSerial(serial)
	if data, err := os.ReadFile(fsJoin(ks.pkiDir, "certs_by_serial", hexStr+".name")); err == nil {
		if n := strings.TrimSpace(string(data)); n != "" {
			name = n
		}
	}
	pair := &cert.Pair{Name: name, CertPEM: certPEM}
	if keyPEM, err := os.ReadFile(ks.keyPath(name)); err == nil {
		pair.KeyPEM = keyPEM
	}
	return pair, nil
}

func (ks *KeyStorage) DeleteByName(name string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	pair, err := ks.getLastByNameLocked(name)
	if err != nil {
		return err
	}
	if serial, err := pair.Serial(); err == nil {
		_ = os.Remove(ks.serialPath(serial))      // best-effort
		_ = os.Remove(ks.nameSidecarPath(serial)) // best-effort
	}
	var firstErr error
	if err := os.Remove(ks.certPath(name)); err != nil && !os.IsNotExist(err) {
		firstErr = err
	}
	if err := os.Remove(ks.keyPath(name)); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (ks *KeyStorage) DeleteBySerial(serial *big.Int) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if err := os.Remove(ks.serialPath(serial)); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(ks.nameSidecarPath(serial)) // best-effort
	return nil
}

// CleanOrphans removes certificate and key files whose serial is not in knownSerials.
// It scans certs_by_serial/, issued/, and the CA cert. Errors from individual file
// removals are accumulated and returned as a joined error.
func (ks *KeyStorage) CleanOrphans(knownSerials map[string]bool) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	var errs []error

	// 1. Scan certs_by_serial/ — remove .pem and .name files for unknown serials.
	serialDir := fsJoin(ks.pkiDir, "certs_by_serial")
	if entries, err := os.ReadDir(serialDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			var serial string
			switch {
			case strings.HasSuffix(name, ".pem"):
				serial = strings.TrimSuffix(name, ".pem")
			case strings.HasSuffix(name, ".name"):
				serial = strings.TrimSuffix(name, ".name")
			default:
				continue
			}
			if !knownSerials[serial] {
				if err := os.Remove(fsJoin(serialDir, name)); err != nil && !os.IsNotExist(err) {
					errs = append(errs, err)
				}
			}
		}
	} else if !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("reading certs_by_serial: %w", err))
	}

	// 2. Scan issued/*.crt — parse cert, check serial, remove orphaned cert.
	// Private keys are NOT removed here: the key file may be shared with a
	// valid cert for the same entity name (e.g. after a renew).
	issuedDir := fsJoin(ks.pkiDir, "issued")
	if entries, err := os.ReadDir(issuedDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".crt") {
				continue
			}
			certPath := fsJoin(issuedDir, e.Name())
			serial, err := serialFromCertFile(certPath)
			if err != nil {
				continue // skip unparseable files
			}
			if !knownSerials[hexSerial(serial)] {
				if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
					errs = append(errs, err)
				}
			}
		}
	} else if !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("reading issued: %w", err))
	}

	// 3. Check ca.crt.
	caPath := fsJoin(ks.pkiDir, "ca.crt")
	if serial, err := serialFromCertFile(caPath); err == nil {
		if !knownSerials[hexSerial(serial)] {
			if err := os.Remove(caPath); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

// serialFromCertFile reads a PEM certificate file and returns its serial number.
func serialFromCertFile(path string) (*big.Int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return c.SerialNumber, nil
}

func (ks *KeyStorage) GetAll() ([]*cert.Pair, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	var pairs []*cert.Pair

	if caPair, err := ks.getLastByNameLocked(ks.caName); err == nil {
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
		if pair, err := ks.getLastByNameLocked(name); err == nil {
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
// Concurrent calls within the same process are serialized by mu.
// Concurrent access from separate processes sharing the same pkiDir is not safe.
type SerialProvider struct {
	path string
	mu   sync.Mutex
}

// NewSerialProvider creates a SerialProvider backed by pkiDir/serial.
func NewSerialProvider(pkiDir string) *SerialProvider {
	return &SerialProvider{path: fsJoin(pkiDir, "serial")}
}

func (sp *SerialProvider) Next() (*big.Int, error) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	data, err := os.ReadFile(sp.path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		data = []byte("01\n")
	}

	hexStr := strings.TrimSpace(string(data))
	n := new(big.Int)
	if _, ok := n.SetString(hexStr, 16); !ok || n.Sign() <= 0 {
		return nil, fmt.Errorf("storage/fs: invalid serial in file: %q", hexStr)
	}

	next := new(big.Int).Add(n, big.NewInt(1))
	nextHex := hexSerial(next)
	if err := writeAtomic(sp.path, []byte(nextHex+"\n")); err != nil {
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
	return writeAtomic(ch.path, pemBytes)
}

func (ch *CRLHolder) Delete() error {
	err := os.Remove(ch.path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
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
		return nil, errors.New("crl: file exists but contains no valid PEM block")
	}
	return x509.ParseRevocationList(block.Bytes)
}

package pki

import (
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"math/big"
	"time"

	"github.com/kemsta/go-easyrsa/cert"
	"github.com/kemsta/go-easyrsa/storage"
	fsstore "github.com/kemsta/go-easyrsa/storage/fs"
)

// ErrNotImplemented is returned by PKI methods not yet implemented.
var ErrNotImplemented = errors.New("not implemented")

// PKI orchestrates all certificate operations.
// All storage dependencies are private — callers interact only through PKI methods.
type PKI struct {
	storage    storage.KeyStorage
	csrStorage storage.CSRStorage
	index      storage.IndexDB
	serial     storage.SerialProvider
	crlHolder  storage.CRLHolder
	config     Config
}

// New constructs a PKI with explicit storage dependencies.
func New(
	cfg Config,
	s storage.KeyStorage,
	csr storage.CSRStorage,
	idx storage.IndexDB,
	sp storage.SerialProvider,
	crl storage.CRLHolder,
) *PKI {
	return &PKI{
		storage:    s,
		csrStorage: csr,
		index:      idx,
		serial:     sp,
		crlHolder:  crl,
		config:     applyConfigDefaults(cfg),
	}
}

// NewWithFS constructs a PKI backed by a filesystem PKI directory
// using the easy-rsa-compatible layout.
func NewWithFS(pkiDir string, cfg Config) (*PKI, error) {
	cfg = applyConfigDefaults(cfg)
	if err := fsstore.InitDirs(pkiDir); err != nil {
		return nil, err
	}
	return &PKI{
		storage:    fsstore.NewKeyStorage(pkiDir, cfg.CAName),
		csrStorage: fsstore.NewCSRStorage(pkiDir),
		index:      fsstore.NewIndexDB(pkiDir),
		serial:     fsstore.NewSerialProvider(pkiDir),
		crlHolder:  fsstore.NewCRLHolder(pkiDir),
		config:     cfg,
	}, nil
}

// applyConfigDefaults fills zero values in cfg with sensible defaults.
func applyConfigDefaults(cfg Config) Config {
	if cfg.KeyAlgo == "" {
		cfg.KeyAlgo = AlgoRSA
	}
	if cfg.KeySize == 0 {
		cfg.KeySize = 2048
	}
	if cfg.Curve == nil {
		cfg.Curve = elliptic.P256()
	}
	if cfg.DefaultDays == 0 {
		cfg.DefaultDays = 825
	}
	if cfg.CADays == 0 {
		cfg.CADays = 3650
	}
	if cfg.CRLDays == 0 {
		cfg.CRLDays = 180
	}
	if cfg.PreExpiryDays == 0 {
		cfg.PreExpiryDays = 90
	}
	if cfg.CAName == "" {
		cfg.CAName = "ca"
	}
	if cfg.DNMode == "" {
		cfg.DNMode = DNModeCNOnly
	}
	return cfg
}

// keyPassphrase resolves the passphrase to use when storing a generated key.
// Returns "" (no encryption) when NoPass is true (config or option).
func (p *PKI) keyPassphrase(o options) string {
	if o.noPass != nil && *o.noPass {
		return ""
	}
	if o.passphrase != "" {
		return o.passphrase
	}
	if p.config.NoPass {
		return ""
	}
	return ""
}

// notImplKeyStorage implements storage.KeyStorage returning ErrNotImplemented.
type notImplKeyStorage struct{}

func (n *notImplKeyStorage) Put(_ *cert.Pair) error                     { return ErrNotImplemented }
func (n *notImplKeyStorage) GetByName(_ string) ([]*cert.Pair, error)   { return nil, ErrNotImplemented }
func (n *notImplKeyStorage) GetLastByName(_ string) (*cert.Pair, error) { return nil, ErrNotImplemented }
func (n *notImplKeyStorage) GetBySerial(_ *big.Int) (*cert.Pair, error) { return nil, ErrNotImplemented }
func (n *notImplKeyStorage) DeleteByName(_ string) error                { return ErrNotImplemented }
func (n *notImplKeyStorage) DeleteBySerial(_ *big.Int) error            { return ErrNotImplemented }
func (n *notImplKeyStorage) GetAll() ([]*cert.Pair, error)              { return nil, ErrNotImplemented }

// notImplCSRStorage implements storage.CSRStorage returning ErrNotImplemented.
type notImplCSRStorage struct{}

func (n *notImplCSRStorage) PutCSR(_ string, _ []byte) error { return ErrNotImplemented }
func (n *notImplCSRStorage) GetCSR(_ string) ([]byte, error) { return nil, ErrNotImplemented }
func (n *notImplCSRStorage) DeleteCSR(_ string) error        { return ErrNotImplemented }
func (n *notImplCSRStorage) ListCSRs() ([]string, error)     { return nil, ErrNotImplemented }

// notImplIndexDB implements storage.IndexDB returning ErrNotImplemented.
type notImplIndexDB struct{}

func (n *notImplIndexDB) Record(_ storage.IndexEntry) error { return ErrNotImplemented }
func (n *notImplIndexDB) Update(_ *big.Int, _ storage.CertStatus, _ time.Time, _ cert.RevocationReason) error {
	return ErrNotImplemented
}
func (n *notImplIndexDB) Query(_ storage.IndexFilter) ([]storage.IndexEntry, error) {
	return nil, ErrNotImplemented
}

// notImplSerialProvider implements storage.SerialProvider returning ErrNotImplemented.
type notImplSerialProvider struct{}

func (n *notImplSerialProvider) Next() (*big.Int, error) { return nil, ErrNotImplemented }

// notImplCRLHolder implements storage.CRLHolder returning ErrNotImplemented.
type notImplCRLHolder struct{}

func (n *notImplCRLHolder) Put(_ []byte) error                { return ErrNotImplemented }
func (n *notImplCRLHolder) Get() (*x509.RevocationList, error) { return nil, ErrNotImplemented }

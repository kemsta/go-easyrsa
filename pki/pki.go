package pki

import (
	"crypto/elliptic"
	"errors"

	"github.com/kemsta/go-easyrsa/storage"
	fsstore "github.com/kemsta/go-easyrsa/storage/fs"
	legacystore "github.com/kemsta/go-easyrsa/storage/legacy"
)

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

// NewWithLegacyFSRO constructs a PKI backed by the legacy v1 filesystem layout
// in read-only mode.
func NewWithLegacyFSRO(pkiDir string, cfg Config) (*PKI, error) {
	cfg = applyConfigDefaults(cfg)
	ks := legacystore.NewKeyStorage(pkiDir, cfg.CAName)
	crl := legacystore.NewCRLHolder(pkiDir)
	return &PKI{
		storage:    ks,
		csrStorage: legacystore.NewCSRStorage(),
		index:      legacystore.NewIndexDB(ks, crl),
		serial:     legacystore.NewSerialProvider(),
		crlHolder:  crl,
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
// Returns an error if NoPass is false (config and option) and no passphrase is provided,
// to prevent silently storing plaintext private keys.
func (p *PKI) keyPassphrase(o options) (string, error) {
	if o.noPass != nil && *o.noPass {
		return "", nil
	}
	if o.passphrase != "" {
		return o.passphrase, nil
	}
	if p.config.NoPass {
		return "", nil
	}
	return "", errors.New("pki: key passphrase required; use WithPassphrase() or WithNoPass()")
}

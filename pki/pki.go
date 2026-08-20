package pki

import (
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/kemsta/go-easyrsa/v2/storage"
	fsstore "github.com/kemsta/go-easyrsa/v2/storage/fs"
	legacystore "github.com/kemsta/go-easyrsa/v2/storage/legacy"
	memorystore "github.com/kemsta/go-easyrsa/v2/storage/memory"
)

// PKI orchestrates all certificate operations.
// All storage dependencies are private — callers interact only through PKI methods.
type PKI struct {
	backend storage.Backend
	config  Config

	// The low-level fields are populated only on an ephemeral PKI copy bound to
	// a backend View or Update callback. Public calls on the durable PKI enter a
	// backend boundary before using them.
	storage    storage.KeyStorage
	csrStorage storage.CSRStorage
	index      storage.IndexDB
	serial     storage.SerialProvider
	crlHolder  storage.CRLHolder
	artifacts  storage.ArtifactStorage
	lifecycle  storage.LifecycleStorage
}

// New constructs a PKI using one aggregate storage backend.
func New(cfg Config, backend storage.Backend) (*PKI, error) {
	cfg = applyConfigDefaults(cfg)
	if err := storage.ValidateEntityName(cfg.CAName); err != nil {
		return nil, fmt.Errorf("pki: invalid CA name: %w", err)
	}
	if backend == nil {
		return nil, errors.New("pki: storage backend is required")
	}
	if validator, ok := backend.(storage.OwnershipValidator); ok {
		if err := storage.ValidateOwnership(validator); err != nil {
			return nil, err
		}
	}
	return &PKI{backend: backend, config: cfg}, nil
}

// OpenWithFS opens a PKI backed by an existing filesystem layout without
// creating directories or files. It is suitable for read-only operations.
func OpenWithFS(pkiDir string, cfg Config) (*PKI, error) {
	cfg = applyConfigDefaults(cfg)
	if err := storage.ValidateEntityName(cfg.CAName); err != nil {
		return nil, fmt.Errorf("pki: invalid CA name: %w", err)
	}
	// Construction is deliberately non-validating and non-mutating so callers
	// can invoke InitPKI and receive ErrForeignStorage from that operation. Every
	// ordinary View/Update still validates ownership in the backend.
	return &PKI{backend: fsstore.NewBackend(pkiDir, cfg.CAName), config: cfg}, nil
}

// NewWithFS constructs a PKI backed by a filesystem PKI directory
// using the easy-rsa-compatible layout, initializing its directories.
func NewWithFS(pkiDir string, cfg Config) (*PKI, error) {
	cfg = applyConfigDefaults(cfg)
	if err := storage.ValidateEntityName(cfg.CAName); err != nil {
		return nil, fmt.Errorf("pki: invalid CA name: %w", err)
	}
	backend := fsstore.NewBackend(pkiDir, cfg.CAName)
	if err := backend.EnsureLayout(); err != nil {
		return nil, wrapForeignStorageError(err, pkiDir, "current PKI filesystem layout")
	}
	pk, err := New(cfg, backend)
	if err != nil {
		return nil, wrapForeignStorageError(err, pkiDir, "current PKI filesystem layout")
	}
	return pk, nil
}

// NewWithMemory constructs an empty transactional in-memory PKI.
func NewWithMemory(cfg Config) (*PKI, error) {
	return New(cfg, memorystore.NewBackend())
}

// NewWithLegacyFSRO constructs a PKI backed by the legacy v1 filesystem layout
// in read-only mode.
func NewWithLegacyFSRO(pkiDir string, cfg Config) (*PKI, error) {
	cfg = applyConfigDefaults(cfg)
	backend := legacystore.NewBackend(pkiDir, cfg.CAName)
	pk, err := New(cfg, backend)
	if err != nil {
		return nil, wrapForeignStorageError(err, pkiDir, "legacy PKI filesystem layout")
	}
	return pk, nil
}

// applyConfigDefaults fills zero values in cfg with sensible defaults.
func wrapForeignStorageError(err error, target, layout string) error {
	if errors.Is(err, storage.ErrForeignStorage) {
		return fmt.Errorf("%s is not empty and does not look like the %s: %w", target, layout, err)
	}
	return err
}

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

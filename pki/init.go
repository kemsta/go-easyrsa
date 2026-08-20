package pki

import "errors"

// InitPKIOptions controls explicit Easy-RSA PKI initialization.
type InitPKIOptions struct {
	// Reset permits replacement of an existing owned PKI. Foreign storage is
	// never replaced.
	Reset bool
}

// InitPKI creates a fresh backend layout. An existing owned PKI is rejected
// unless Reset is true. The library never prompts.
func (p *PKI) InitPKI(options InitPKIOptions) error {
	if p == nil || p.backend == nil {
		return errors.New("pki: storage backend is required")
	}
	if p.bound() {
		return errors.New("pki: InitPKI cannot run inside a storage transaction")
	}
	return p.backend.Initialize(options.Reset)
}

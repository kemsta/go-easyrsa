package pki

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509/pkix"
)

// KeyAlgo specifies the algorithm used for key generation.
type KeyAlgo string

const (
	AlgoRSA     KeyAlgo = "rsa"
	AlgoECDSA   KeyAlgo = "ecdsa"
	AlgoEd25519 KeyAlgo = "ed25519"
)

// DNMode controls which fields are included in certificate subject DNs.
type DNMode string

const (
	DNModeCNOnly DNMode = "cn_only"
	DNModeOrg    DNMode = "org"
)

// Config holds PKI-wide defaults. All fields can be overridden per-operation
// via Option functions.
type Config struct {
	// Crypto defaults — overridable per-operation via Option
	KeyAlgo    KeyAlgo        // rsa | ecdsa | ed25519 (default: rsa)
	KeySize    int            // RSA only: 2048/3072/4096 (default: 2048)
	Curve      elliptic.Curve // ECDSA only: P-256, P-384, P-521 (default: P-256)
	DigestAlgo crypto.Hash    // SHA-256, SHA-384, SHA-512 (default: SHA-256)

	// Certificate validity defaults
	DefaultDays   int // end-entity cert validity (default: 825)
	CADays        int // CA cert validity (default: 3650)
	CRLDays       int // CRL validity (default: 180)
	PreExpiryDays int // warn window for ShowExpiring (default: 90)

	// Subject defaults
	SubjTemplate pkix.Name
	DNMode       DNMode // cn_only | org (default: cn_only)

	// Serial number generation
	RandomSerial bool // true = random 128-bit serial; false = incremental (default: true)

	// Key protection defaults
	// The library stores key PEM bytes as returned by generation.
	// NoPass=true → keys are stored unencrypted (PKCS8 plaintext).
	// NoPass=false → per-operation WithPassphrase() must supply the passphrase,
	//                otherwise generation fails rather than silently storing plaintext.
	NoPass bool // default: false (require explicit WithPassphrase or WithNoPass per-op)

	// CA key passphrase — used when decrypting the CA private key for signing.
	// Equivalent to EASYRSA_PASSIN for the CA key.
	// If empty and the CA key is encrypted, signing operations return an error.
	CAPassphrase string

	// Netscape extensions (deprecated, for compatibility)
	NetscapeExtensions bool   // default: false
	NetscapeComment    string // default: "Easy-RSA Generated Certificate"

	// CA name in storage
	CAName string // default: "ca"
}

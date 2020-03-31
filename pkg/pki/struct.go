package pki

import (
	"crypto/x509/pkix"
	"github.com/kemsta/go-easyrsa/pkg/pair"
	"math/big"
)

// Key storage interface
type KeyStorage interface {
	Put(pair *pair.X509Pair) error                       // Put new pair to Storage. Overwrite if already exist.
	GetByCN(cn string) ([]*pair.X509Pair, error)         // Get all keypairs by CN.
	GetLastByCn(cn string) (*pair.X509Pair, error)       // Get last pair by CN.
	GetBySerial(serial *big.Int) (*pair.X509Pair, error) // Get one keypair by serial.
	DeleteByCn(cn string) error                          // Delete all keypairs by CN.
	DeleteBySerial(serial *big.Int) error                // Delete one keypair by serial.
	GetAll() ([]*pair.X509Pair, error)                   // Get all keypair
}

// Serial provider interface
type SerialProvider interface {
	Next() (*big.Int, error) // Next return next uniq serial
}

// Certificate revocation list holder interface
type CRLHolder interface {
	Put([]byte) error                    // Put file content for crl
	Get() (*pkix.CertificateList, error) // Get current revoked cert list
}

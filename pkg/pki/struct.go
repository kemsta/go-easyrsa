package pki

import (
	"crypto/x509"
	"github.com/kemsta/go-easyrsa/pkg/pair"
	"math/big"
)

// KeyStorage storage interface
type KeyStorage interface {
	Put(pair *pair.X509Pair) error                       // Put new pair to KeyStorage.
	GetByCN(cn string) ([]*pair.X509Pair, error)         // Get all keypairs by CN.
	GetLastByCn(cn string) (*pair.X509Pair, error)       // Get last pair by CN.
	GetBySerial(serial *big.Int) (*pair.X509Pair, error) // Get one keypair by serial.
	DeleteByCN(cn string) error                          // Delete all keypairs by CN.
	DeleteBySerial(serial *big.Int) error                // Delete one keypair by serial.
	GetAll() ([]*pair.X509Pair, error)                   // Get all keypair
}

// SerialProvider provider interface
type SerialProvider interface {
	Next() (*big.Int, error) // Next return uniq serial
}

// CRLHolder is a certificate revocation list holder interface
type CRLHolder interface {
	Put([]byte) error                   // Put file content for crl
	Get() (*x509.RevocationList, error) // Get current revoked cert list
}

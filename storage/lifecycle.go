package storage

import (
	"fmt"
	"math/big"
	"strings"
)

// LifecycleStorage moves PKI files between Easy-RSA lifecycle locations. It
// does not update the certificate index or generate a CRL.
type LifecycleStorage interface {
	MoveIssuedToExpired(name string) error
	MoveIssuedToRenewed(name string) error
	MoveIssuedToRevoked(name string, serial *big.Int) error
	MoveExpiredToRevoked(name string, serial *big.Int) error
	MoveRenewedToRevoked(name string, serial *big.Int) error
	GetRenewedCertificate(name string) ([]byte, error)
}

// ValidateEntityName rejects names that could escape a backend's fixed PKI
// layout.
func ValidateEntityName(name string) error {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "..") || strings.ContainsAny(name, "/\\") || strings.ContainsRune(name, '\x00') {
		return fmt.Errorf("storage: invalid entity name %q", name)
	}
	return nil
}

// ValidateSerial rejects nil and non-positive certificate serials.
func ValidateSerial(serial *big.Int) error {
	if serial == nil || serial.Sign() <= 0 {
		return fmt.Errorf("storage: certificate serial must be positive")
	}
	return nil
}

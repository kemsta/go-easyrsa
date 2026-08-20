package storage

import (
	"fmt"
	"math/big"
	"strings"
)

// LifecycleRecord is one archived certificate and its optional associated
// private key and request.
type LifecycleRecord struct {
	Name           string
	Serial         *big.Int
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	CSRPEM         []byte
	AssetsArchived bool
}

// LifecycleState is the storage-agnostic representation used by snapshots.
type LifecycleState struct {
	Expired []LifecycleRecord
	Renewed []LifecycleRecord
	Revoked []LifecycleRecord
}

// LifecycleStorage moves PKI files between Easy-RSA lifecycle locations. It
// does not update the certificate index or generate a CRL.
type LifecycleStorage interface {
	MoveIssuedToExpired(name string, serial *big.Int) error
	MoveIssuedToRenewed(name string, serial *big.Int) error
	MoveIssuedToRevoked(name string, serial *big.Int) error
	MoveExpiredToRevoked(name string, serial *big.Int) error
	MoveRenewedToRevoked(name string, serial *big.Int) error
	GetExpiredCertificate(name string) ([]byte, error)
	GetRenewedCertificate(name string) ([]byte, error)
	ExportState() (LifecycleState, error)
	ReplaceState(LifecycleState) error
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

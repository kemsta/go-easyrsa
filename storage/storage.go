package storage

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/kemsta/go-easyrsa/cert"
)

// Sentinel errors returned by storage implementations.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
)

// CertStatus represents the current state of a certificate in the index.
type CertStatus string

const (
	StatusValid   CertStatus = "V"
	StatusRevoked CertStatus = "R"
	StatusExpired CertStatus = "E"
)

// IndexEntry is a single record in the certificate database,
// analogous to a line in easy-rsa's index.txt.
type IndexEntry struct {
	Status           CertStatus
	ExpiresAt        time.Time
	RevokedAt        time.Time // zero if not revoked
	Serial           *big.Int
	Subject          pkix.Name
	RevocationReason cert.RevocationReason
}

// IndexFilter constrains Query results.
type IndexFilter struct {
	Status *CertStatus // nil = all statuses
	Name   string      // empty = all names; matched against Subject CN
}

// KeyStorage stores key+certificate pairs.
// The Name field on Pair is the storage key (entity name).
type KeyStorage interface {
	Put(pair *cert.Pair) error
	GetByName(name string) ([]*cert.Pair, error)   // returns ErrNotFound if none
	GetLastByName(name string) (*cert.Pair, error) // highest serial; ErrNotFound if none
	GetBySerial(serial *big.Int) (*cert.Pair, error)
	DeleteByName(name string) error
	DeleteBySerial(serial *big.Int) error
	GetAll() ([]*cert.Pair, error)
}

// CSRStorage stores Certificate Signing Requests (PEM-encoded).
type CSRStorage interface {
	PutCSR(name string, csrPEM []byte) error
	GetCSR(name string) ([]byte, error) // ErrNotFound if absent
	DeleteCSR(name string) error
	ListCSRs() ([]string, error)
}

// IndexDB is the certificate database, analogous to easy-rsa's index.txt.
// It tracks all issued certificates and their current status.
type IndexDB interface {
	Record(entry IndexEntry) error
	// Update changes the status of the entry identified by serial.
	// revokedAt and reason are only meaningful when status == StatusRevoked.
	Update(serial *big.Int, status CertStatus, revokedAt time.Time, reason cert.RevocationReason) error
	// RecordAndUpdate atomically appends a new entry and, if oldSerial is
	// found in the index, updates its status — all in a single write. This
	// prevents a partial-failure window between Record and Update for renewals.
	// If oldSerial is not in the index (e.g. the cert was created by an
	// external tool), the new entry is still committed without error.
	RecordAndUpdate(newEntry IndexEntry, oldSerial *big.Int, status CertStatus, revokedAt time.Time, reason cert.RevocationReason) error
	Query(filter IndexFilter) ([]IndexEntry, error)
}

// HexSerial returns n as an uppercase, even-length hex string (e.g. 1 → "01").
func HexSerial(n *big.Int) string {
	h := strings.ToUpper(n.Text(16))
	if len(h)%2 != 0 {
		h = "0" + h
	}
	return h
}

// SerialProvider generates monotonically increasing serial numbers.
type SerialProvider interface {
	Next() (*big.Int, error)
}

// CRLHolder stores and retrieves the Certificate Revocation List.
type CRLHolder interface {
	Put(pemBytes []byte) error
	Get() (*x509.RevocationList, error) // returns empty list (not error) if none exists
}

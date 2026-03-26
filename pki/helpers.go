package pki

import (
	"encoding/pem"
	"errors"
	"strings"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

// pemEncodeCert PEM-encodes a DER certificate.
func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// pemEncodeCSR PEM-encodes a DER certificate request.
func pemEncodeCSR(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// validateEntityName rejects names that would escape the PKI directory via
// path traversal or that contain characters unsafe for use as a filename.
func validateEntityName(name string) error {
	if name == "" {
		return errors.New("pki: entity name must not be empty")
	}
	if strings.ContainsAny(name, "/\\") {
		return errors.New("pki: entity name must not contain path separators ('/' or '\\')")
	}
	if strings.Contains(name, "..") {
		return errors.New("pki: entity name must not contain '..'")
	}
	if name == "." {
		return errors.New("pki: entity name must not be '.'")
	}
	if strings.ContainsRune(name, 0) {
		return errors.New("pki: entity name must not contain null bytes")
	}
	return nil
}

func isReadOnly(v any) bool {
	ro, ok := v.(storage.ReadOnly)
	return ok && ro.ReadOnly()
}

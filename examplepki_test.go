package easyrsa

import (
	"crypto/x509/pkix"
	"path/filepath"
)

func ExampleNewPKI() {
	storDir := "/var/tmp"
	storage := NewDirKeyStorage(storDir)
	serialProvider := NewFileSerialProvider(filepath.Join(storDir, "serial"))
	crlHolder := NewFileCRLHolder(filepath.Join(storDir, "crl.pem"))
	NewPKI(storage, serialProvider, crlHolder, pkix.Name{})
}

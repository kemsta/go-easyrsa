package pki

import "encoding/pem"

// pemEncodeCert PEM-encodes a DER certificate.
func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// pemEncodeCSR PEM-encodes a DER certificate request.
func pemEncodeCSR(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

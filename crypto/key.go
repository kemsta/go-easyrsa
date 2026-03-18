package pkicrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// GenKey generates a private key. algo must be "rsa", "ecdsa", or "ed25519".
// RSA defaults to 2048 bits if keySize is 0. ECDSA defaults to P-256 if curve is nil.
func GenKey(algo string, keySize int, curve elliptic.Curve) (crypto.PrivateKey, error) {
	switch algo {
	case "ecdsa":
		if curve == nil {
			curve = elliptic.P256()
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default: // "rsa" or empty
		if keySize == 0 {
			keySize = 2048
		}
		return rsa.GenerateKey(rand.Reader, keySize)
	}
}

// MarshalPrivateKey marshals a private key to PKCS8 PEM.
// If passphrase is non-empty, the PEM block is encrypted with AES-256-CBC.
// If passphrase is empty, produces plaintext PKCS8.
func MarshalPrivateKey(key crypto.PrivateKey, passphrase string) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if passphrase != "" {
		//nolint:staticcheck // EncryptPEMBlock is deprecated but provides the simplest interoperable encryption
		block, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", der, []byte(passphrase), x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(block), nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// UnmarshalPrivateKey parses a PKCS8 PEM private key, handling both encrypted
// (DEK-Info headers) and unencrypted forms. Also falls back to PKCS1 and EC formats.
func UnmarshalPrivateKey(pemBytes []byte, passphrase string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("pkicrypto: failed to decode PEM block")
	}
	var der []byte
	//nolint:staticcheck // IsEncryptedPEMBlock is deprecated but needed for compatibility
	if x509.IsEncryptedPEMBlock(block) {
		var err error
		//nolint:staticcheck // DecryptPEMBlock is deprecated but needed for compatibility
		der, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return nil, err
		}
	} else {
		der = block.Bytes
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("pkicrypto: failed to parse private key")
}

// PublicKey extracts the public key from a private key.
func PublicKey(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	default:
		return nil, errors.New("pkicrypto: unsupported key type")
	}
}

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
	"fmt"

	"github.com/youmark/pkcs8"
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

var encryptedPKCS8Opts = &pkcs8.Opts{
	Cipher: pkcs8.AES256CBC,
	KDFOpts: pkcs8.PBKDF2Opts{
		SaltSize:       16,
		IterationCount: 100_000,
		HMACHash:       crypto.SHA256,
	},
}

// MarshalPrivateKey marshals a private key to PKCS#8 PEM.
// If passphrase is non-empty, it produces a PBES2-encrypted
// EncryptedPrivateKeyInfo. Otherwise it produces plaintext PrivateKeyInfo.
func MarshalPrivateKey(key crypto.PrivateKey, passphrase string) ([]byte, error) {
	if passphrase != "" {
		der, err := pkcs8.MarshalPrivateKey(key, []byte(passphrase), encryptedPKCS8Opts)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// UnmarshalPrivateKey parses PKCS#8 PEM, including standard PBES2 and legacy
// DEK-Info encryption. It also falls back to PKCS#1 and SEC1 EC formats.
func UnmarshalPrivateKey(pemBytes []byte, passphrase string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("pkicrypto: failed to decode PEM block")
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		if passphrase == "" {
			return nil, errors.New("pkicrypto: passphrase required for encrypted PKCS#8 key")
		}
		key, err := parseEncryptedPKCS8(block.Bytes, passphrase)
		if err != nil {
			return nil, fmt.Errorf("pkicrypto: decrypt PKCS#8 key: %w", err)
		}
		return key, nil
	}

	var der []byte
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck // legacy PEM compatibility
		var err error
		der, err = x509.DecryptPEMBlock(block, []byte(passphrase)) //nolint:staticcheck // legacy PEM compatibility
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

func parseEncryptedPKCS8(der []byte, passphrase string) (key crypto.PrivateKey, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			key = nil
			err = fmt.Errorf("invalid encrypted PKCS#8 data: %v", recovered)
		}
	}()
	return pkcs8.ParsePKCS8PrivateKey(der, []byte(passphrase))
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

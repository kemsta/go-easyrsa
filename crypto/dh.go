package pkicrypto

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
)

// dhParams is the ASN.1 structure for DH parameters.
type dhParams struct {
	P *big.Int
	G *big.Int
}

// GenDHParams generates Diffie-Hellman parameters (safe prime p, generator g=2).
// bits specifies the bit length of p (use 512 for tests, 2048 for production).
func GenDHParams(bits int) ([]byte, error) {
	p, err := generateSafePrime(bits)
	if err != nil {
		return nil, err
	}
	der, err := asn1.Marshal(dhParams{P: p, G: big.NewInt(2)})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "DH PARAMETERS",
		Bytes: der,
	}), nil
}

// generateSafePrime generates a safe prime p of the given bit length:
// p = 2q+1 where both p and q are prime.
func generateSafePrime(bits int) (*big.Int, error) {
	two := big.NewInt(2)
	one := big.NewInt(1)
	for {
		q, err := rand.Prime(rand.Reader, bits-1)
		if err != nil {
			return nil, err
		}
		p := new(big.Int).Mul(q, two)
		p.Add(p, one)
		if p.ProbablyPrime(20) {
			return p, nil
		}
	}
}

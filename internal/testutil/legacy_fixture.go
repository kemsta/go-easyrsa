package testutil

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kemsta/go-easyrsa/v2/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/v2/crypto"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
)

// LegacyFixture contains a v1-style PKI tree written to disk for tests.
type LegacyFixture struct {
	Dir           string
	CAPair        *cert.Pair
	ClientOld     *cert.Pair
	ClientCurrent *cert.Pair
	ExpiredPair   *cert.Pair
	RevokedPair   *cert.Pair
	CRLPEM        []byte
}

// WriteLegacyFixture creates a v1-style filesystem layout under dir:
//
//	dir/<name>/<serial>.crt
//	dir/<name>/<serial>.key
//
// plus dir/crl.pem.
func WriteLegacyFixture(t *testing.T, dir string) LegacyFixture {
	t.Helper()

	ks, cs, idx, sp, crl := memory.New()
	p, err := pki.New(pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024}, ks, cs, idx, sp, crl)
	mustNoError(t, err)

	caPair, err := p.BuildCA()
	mustNoError(t, err)

	clientOld, err := p.BuildClientFull("client1", pki.WithDays(365))
	mustNoError(t, err)

	clientCurrent, err := p.Renew("client1", pki.WithDays(730))
	mustNoError(t, err)

	expiredPair, err := p.BuildClientFull(
		"expired1",
		pki.WithNotBefore(time.Now().AddDate(0, 0, -10)),
		pki.WithNotAfter(time.Now().AddDate(0, 0, -1)),
	)
	mustNoError(t, err)

	revokedPair, err := p.BuildClientFull("revoked1", pki.WithDays(365))
	mustNoError(t, err)
	mustNoError(t, p.Revoke("revoked1", cert.ReasonKeyCompromise))
	crlPEM, err := p.GenCRL()
	mustNoError(t, err)

	clientOld = clonePair(t, clientOld)
	clientCurrent = clonePair(t, clientCurrent)
	expiredPair = clonePair(t, expiredPair)
	revokedPair = clonePair(t, revokedPair)
	caPair = clonePair(t, caPair)

	clientOld.KeyPEM = mustPKCS1PEM(t, clientOld.KeyPEM)
	clientCurrent.KeyPEM = mustPKCS1PEM(t, clientCurrent.KeyPEM)

	for _, pair := range []*cert.Pair{caPair, clientOld, clientCurrent, expiredPair, revokedPair} {
		mustNoError(t, writeLegacyPair(dir, pair))
	}
	mustNoError(t, os.WriteFile(filepath.Join(dir, "crl.pem"), crlPEM, 0644))

	return LegacyFixture{
		Dir:           dir,
		CAPair:        caPair,
		ClientOld:     clientOld,
		ClientCurrent: clientCurrent,
		ExpiredPair:   expiredPair,
		RevokedPair:   revokedPair,
		CRLPEM:        crlPEM,
	}
}

func writeLegacyPair(dir string, pair *cert.Pair) error {
	serial, err := pair.Serial()
	if err != nil {
		return err
	}
	base := filepath.Join(dir, pair.Name)
	if err := os.MkdirAll(base, 0755); err != nil {
		return err
	}
	serialHex := serial.Text(16)
	if err := os.WriteFile(filepath.Join(base, serialHex+".crt"), pair.CertPEM, 0644); err != nil {
		return err
	}
	if pair.KeyPEM != nil {
		if err := os.WriteFile(filepath.Join(base, serialHex+".key"), pair.KeyPEM, 0600); err != nil {
			return err
		}
	}
	return nil
}

func mustPKCS1PEM(t *testing.T, keyPEM []byte) []byte {
	t.Helper()
	key, err := pkicrypto.UnmarshalPrivateKey(keyPEM, "")
	mustNoError(t, err)
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", key)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
}

func clonePair(t *testing.T, pair *cert.Pair) *cert.Pair {
	t.Helper()
	cp := &cert.Pair{Name: pair.Name}
	if pair.CertPEM != nil {
		cp.CertPEM = append([]byte(nil), pair.CertPEM...)
	}
	if pair.KeyPEM != nil {
		cp.KeyPEM = append([]byte(nil), pair.KeyPEM...)
	}
	return cp
}

// MustSerial returns a copy of the certificate serial number.
func MustSerial(t *testing.T, pair *cert.Pair) *big.Int {
	t.Helper()
	serial, err := pair.Serial()
	mustNoError(t, err)
	return new(big.Int).Set(serial)
}

func mustNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

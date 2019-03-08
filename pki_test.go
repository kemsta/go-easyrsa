package easyrsa

import (
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/common/log"
	"github.com/stretchr/testify/assert"
)

var testData = "test_data/pki/"

func TestPki_NewCa(t *testing.T) {
	pki, cleanup := getTmpPki()
	defer cleanup()
	t.Run("create ca and not write", func(t *testing.T) {
		got, err := pki.NewCa(false)
		assert.NoError(t, err)
		assert.NotNil(t, got)
		assert.NotEmpty(t, got.CertPemBytes)
		assert.NotEmpty(t, got.KeyPemBytes)
	})
	t.Run("create ca and write", func(t *testing.T) {
		got, err := pki.NewCa(true)
		assert.NoError(t, err)
		assert.NotNil(t, got)
		assert.NotEmpty(t, got.CertPemBytes)
		assert.NotEmpty(t, got.KeyPemBytes)
	})
	t.Run("get ca by cn", func(t *testing.T) {
		got, err := pki.Storage.GetByCN("ca")
		assert.NoError(t, err)
		assert.NotNil(t, got)
		assert.Len(t, got, 1)
	})
	t.Run("get ca by serial", func(t *testing.T) {
		got, err := pki.Storage.GetBySerial(big.NewInt(2))
		assert.NoError(t, err)
		assert.NotNil(t, got)
		assert.NotEmpty(t, got.CertPemBytes)
		assert.NotEmpty(t, got.KeyPemBytes)
	})
	t.Run("decode ca", func(t *testing.T) {
		ca, err := pki.Storage.GetByCN("ca")
		key, cert, err := ca[0].Decode()
		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.NotNil(t, cert)
		assert.Equal(t, cert.SerialNumber, big.NewInt(2))
		assert.True(t, cert.IsCA)
		assert.Equal(t, cert.Subject.CommonName, "ca")
	})
}

func TestPKI_newCert(t *testing.T) {
	pki, cleanup := getTmpPki()
	defer cleanup()
	ca, _ := pki.NewCa(true)
	t.Run("create server cert and write", func(t *testing.T) {
		got, err := pki.newCert(ca, true, "server", true)
		assert.NoError(t, err)
		assert.NotNil(t, got)
		assert.NotEmpty(t, got.CertPemBytes)
		assert.NotEmpty(t, got.KeyPemBytes)
	})
	t.Run("get cert by cn", func(t *testing.T) {
		got, err := pki.Storage.GetByCN("server")
		assert.NoError(t, err)
		assert.NotNil(t, got)
		assert.Len(t, got, 1)
	})
	t.Run("get cert by serial", func(t *testing.T) {
		got, err := pki.Storage.GetBySerial(big.NewInt(2))
		assert.NoError(t, err)
		assert.NotNil(t, got)
		assert.NotEmpty(t, got.CertPemBytes)
		assert.NotEmpty(t, got.KeyPemBytes)
	})
	t.Run("decode cert", func(t *testing.T) {
		ca, err := pki.Storage.GetByCN("server")
		key, cert, err := ca[0].Decode()
		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.NotNil(t, cert)
		assert.Equal(t, cert.SerialNumber, big.NewInt(2))
		assert.Equal(t, cert.Subject.CommonName, "server")
	})
}

func getTmpPki() (*PKI, func()) {
	_ = os.MkdirAll(testData, 0777)
	storDir, err := filepath.Abs(testData)
	_ = os.MkdirAll(storDir, 0777)
	storage := NewDirKeyStorage(storDir)
	serialProvider := NewFileSerialProvider(filepath.Join(storDir, "serial"))
	pki := NewPKI(storage, serialProvider, pkix.Name{})
	if err != nil {
		log.Fatalln("can`t create pki")
	}

	return pki, func() {
		_ = os.RemoveAll(storDir)
	}
}

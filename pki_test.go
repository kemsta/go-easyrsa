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

var testData = "test/pki/"

func TestPki_NewCa(t *testing.T) {
	pki, cleanup := getTmpPki()
	defer cleanup()
	t.Run("create ca and write", func(t *testing.T) {
		got, err := pki.NewCa()
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
		got, err := pki.Storage.GetBySerial(big.NewInt(1))
		assert.NoError(t, err)
		assert.NotNil(t, got)
		assert.NotEmpty(t, got.CertPemBytes)
		assert.NotEmpty(t, got.KeyPemBytes)
	})
	t.Run("decode ca", func(t *testing.T) {
		ca, _ := pki.Storage.GetByCN("ca")
		key, cert, err := ca[0].Decode()
		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.NotNil(t, cert)
		assert.Equal(t, cert.SerialNumber, big.NewInt(1))
		assert.True(t, cert.IsCA)
		assert.Equal(t, cert.Subject.CommonName, "ca")
	})
}

func TestPKI_newCert(t *testing.T) {
	pki, cleanup := getTmpPki()
	defer cleanup()
	_, _ = pki.NewCa()
	t.Run("create server cert and write", func(t *testing.T) {
		got, err := pki.NewCert("server", true)
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
		ca, _ := pki.Storage.GetByCN("server")
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
	crlHolder := NewFileCRLHolder(filepath.Join(storDir, "crl.pem"))
	pki := NewPKI(storage, serialProvider, crlHolder, pkix.Name{})
	if err != nil {
		log.Fatalln("can`t create pki")
	}

	return pki, func() {
		_ = os.RemoveAll(storDir)
	}
}

func TestPKI_getCRL(t *testing.T) {
	pki, cleanup := getTmpPki()
	defer cleanup()
	t.Run("get crl", func(t *testing.T) {
		list, err := pki.GetCRL()
		assert.NoError(t, err)
		assert.NotNil(t, list)
	})
}

func TestPKI_RevokeOne(t *testing.T) {
	pki, cleanup := getTmpPki()
	defer cleanup()
	_, _ = pki.NewCa()
	_, _ = pki.NewCert("server", true)
	_, _ = pki.NewCert("server", true)
	_, _ = pki.NewCert("cert", false)
	t.Run("revoke", func(t *testing.T) {
		err := pki.RevokeOne(big.NewInt(300))
		assert.NoError(t, err)
		list, _ := pki.GetCRL()
		assert.Equal(t, list.TBSCertList.RevokedCertificates[0].SerialNumber, big.NewInt(300))
	})
}

func TestPKI_IsRevoked(t *testing.T) {
	pki, cleanup := getTmpPki()
	defer cleanup()
	_, _ = pki.NewCa()
	_, _ = pki.NewCert("server", true)
	_, _ = pki.NewCert("server", true)
	_, _ = pki.NewCert("cert", false)
	t.Run("revoke", func(t *testing.T) {
		err := pki.RevokeOne(big.NewInt(4))
		assert.NoError(t, err)
		assert.True(t, pki.IsRevoked(big.NewInt(4)))
		assert.False(t, pki.IsRevoked(big.NewInt(1)))
		assert.False(t, pki.IsRevoked(big.NewInt(42)))
	})
}

func TestPKI_RevokeAllByCN(t *testing.T) {
	pki, cleanup := getTmpPki()
	defer cleanup()
	_, _ = pki.NewCa()
	_, _ = pki.NewCert("server", true)
	_, _ = pki.NewCert("server", true)
	_, _ = pki.NewCert("cert", false)
	t.Run("revoke", func(t *testing.T) {
		err := pki.RevokeAllByCN("server")
		assert.NoError(t, err)
		list, _ := pki.GetCRL()
		assert.Len(t, list.TBSCertList.RevokedCertificates, 2)
		assert.Equal(t, list.TBSCertList.RevokedCertificates[0].SerialNumber, big.NewInt(2))
	})
}

func TestPKI_GetLastCA(t *testing.T) {
	pki, cleanup := getTmpPki()
	defer cleanup()
	t.Run("empty ca", func(t *testing.T) {
		pair, err := pki.GetLastCA()
		assert.Error(t, err)
		assert.Nil(t, pair)
	})
	t.Run("one ca", func(t *testing.T) {
		_, _ = pki.NewCa()
		pair, err := pki.GetLastCA()
		assert.NoError(t, err)
		assert.NotNil(t, pair)
		assert.Equal(t, pair.CN, "ca")
		assert.Equal(t, pair.Serial, big.NewInt(1))
	})
	t.Run("5 ca", func(t *testing.T) {
		_, _ = pki.NewCa()
		_, _ = pki.NewCa()
		_, _ = pki.NewCa()
		_, _ = pki.NewCa()
		pair, err := pki.GetLastCA()
		assert.NoError(t, err)
		assert.NotNil(t, pair)
		assert.Equal(t, pair.CN, "ca")
		assert.Equal(t, pair.Serial, big.NewInt(5))
	})
}

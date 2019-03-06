package pki

import (
	"crypto/x509/pkix"
	"github.com/prometheus/common/log"
	"io/ioutil"
	"os"
	"testing"
)

var testData = "../test_data/pki/"

func TestPki_NewCa(t *testing.T) {
	pki, cleanup := getTmpPki()
	defer cleanup()
	t.Run("create ca and not write", func(t *testing.T) {
		got, err := pki.NewCa(false)
		if err != nil {
			t.Errorf("PKI.NewCa() error = %v", err)
			return
		}
		if len(got.CertPemBytes) == 0 {
			t.Error("PKI.NewCa() cert bytes empty")
		}
		if len(got.KeyPemBytes) == 0 {
			t.Error("PKI.NewCa() key bytes empty")
		}
	})
	t.Run("create ca and write", func(t *testing.T) {
		got, err := pki.NewCa(true)
		if err != nil {
			t.Errorf("PKI.NewCa() error = %v", err)
			return
		}
		if len(got.CertPemBytes) == 0 {
			t.Error("PKI.NewCa() cert bytes empty")
		}
		if len(got.KeyPemBytes) == 0 {
			t.Error("PKI.NewCa() key bytes empty")
		}
	})
}

func getTmpPki() (*PKI, func()) {
	_ = os.MkdirAll(testData, 0777)
	tmpDir, err := ioutil.TempDir(testData, "tmpPki")
	if err != nil {
		log.Fatalln("can`t create tmp dir")
	}
	_ = os.MkdirAll(tmpDir, 0777)
	pki, err := NewPki(tmpDir, pkix.Name{})
	if err != nil {
		log.Fatalln("can`t create pki")
	}

	return pki, func() {
		_ = os.RemoveAll(tmpDir)
	}
}

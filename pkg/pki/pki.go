package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/kemsta/go-easyrsa/internal/fsStorage"
	"github.com/kemsta/go-easyrsa/pkg/pair"
	"math/big"
	"os"
	"path"
	"sort"
	"time"
)

const (
	PEMCertificateBlock   string = "CERTIFICATE"     // pem block header for x509.Certificate
	PEMRSAPrivateKeyBlock        = "RSA PRIVATE KEY" // pem block header for rsa.PrivateKey
	PEMx509CRLBlock              = "X509 CRL"        // pem block header for CRL
	DefaultKeySizeBytes   int    = 2048              // default key size in bytes
	DefaultExpireYears           = 99                // default expire time for certs
)

// PKI struct holder
type PKI struct {
	Storage        KeyStorage
	serialProvider SerialProvider
	crlHolder      CRLHolder
	subjTemplate   pkix.Name
}

// NewPKI PKI struct "constructor"
func NewPKI(storage KeyStorage, sp SerialProvider, crlHolder CRLHolder, subjTemplate pkix.Name) *PKI {
	return &PKI{Storage: storage, serialProvider: sp, crlHolder: crlHolder, subjTemplate: subjTemplate}
}

// Init default pki with file storages
func InitPKI(pkiDir string, subjTemplate *pkix.Name) (*PKI, error) {
	if subjTemplate == nil {
		subjTemplate = &pkix.Name{}
	}
	pki := NewPKI(fsStorage.NewDirKeyStorage(pkiDir),
		fsStorage.NewFileSerialProvider(path.Join(pkiDir, "serial")),
		fsStorage.NewFileCRLHolder(path.Join(pkiDir, "crl.pem")),
		*subjTemplate)

	if _, err := os.Stat(pkiDir); os.IsNotExist(err) {
		if err := os.MkdirAll(pkiDir, 0750); err != nil {
			return nil, fmt.Errorf("can't create %v: %w", pkiDir, err)
		}
	}
	return pki, nil
}

// NewCa creating new version self signed CA pair
func (p *PKI) NewCa(opts ...Option) (*pair.X509Pair, error) {
	key, err := rsa.GenerateKey(rand.Reader, DefaultKeySizeBytes)
	if err != nil {
		return nil, fmt.Errorf("can`t generate key: %w", err)
	}

	subj := p.subjTemplate
	subj.CommonName = "ca"

	serial, err := p.serialProvider.Next()
	if err != nil {
		return nil, fmt.Errorf("can`t get next serial: %w", err)
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               subj,
		NotBefore:             now.Add(-10 * time.Minute).UTC(),
		NotAfter:              now.Add(time.Duration(24*365*DefaultExpireYears) * time.Hour).UTC(),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	Apply(opts, &template)

	certificate, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("can`t create cert: %w", err)
	}

	res := pair.NewX509Pair(
		pem.EncodeToMemory(&pem.Block{
			Type:  PEMRSAPrivateKeyBlock,
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}),
		pem.EncodeToMemory(&pem.Block{
			Type:  PEMCertificateBlock,
			Bytes: certificate,
		}),
		"ca",
		serial)
	err = p.Storage.Put(res)
	if err != nil {
		return nil, fmt.Errorf("can't put generated cert into storage: %w", err)
	}
	return res, nil
}

// NewCert generate new pair signed by last CA key
func (p *PKI) NewCert(cn string, opts ...Option) (*pair.X509Pair, error) {
	caPair, err := p.GetLastCA()
	if err != nil {
		return nil, fmt.Errorf("can`t get ca pair: %w", err)
	}
	caKey, caCert, err := caPair.Decode()
	if err != nil {
		return nil, fmt.Errorf("can`t parse ca pair: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("can`t create private key: %w", err)
	}

	serial, err := p.serialProvider.Next()
	if err != nil {
		return nil, err
	}

	val, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 2}) // setting nsCertType to Client Type
	if err != nil {
		return nil, fmt.Errorf("can not marshal nsCertType: %w", err)
	}

	now := time.Now()
	subj := p.subjTemplate
	subj.CommonName = cn
	tmpl := x509.Certificate{
		NotBefore:             now.Add(-10 * time.Minute).UTC(),
		NotAfter:              now.Add(time.Duration(24*365*DefaultExpireYears) * time.Hour).UTC(),
		SerialNumber:          serial,
		Subject:               subj,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1},
				Value: val,
			},
		},
	}

	Apply(opts, &tmpl)

	// Sign with CA's private key
	cert, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("certificate cannot be created: %w", err)
	}

	priKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  PEMRSAPrivateKeyBlock,
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  PEMCertificateBlock,
		Bytes: cert,
	})

	res := pair.NewX509Pair(priKeyPem, certPem, cn, serial)

	err = p.Storage.Put(res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// GetCRL return current revoke list
func (p *PKI) GetCRL() (*pkix.CertificateList, error) {
	return p.crlHolder.Get()
}

// GetLastCA return last CA pair
func (p *PKI) GetLastCA() (*pair.X509Pair, error) {
	return p.Storage.GetLastByCn("ca")
}

// RevokeOne revoke one pair with serial
func (p *PKI) RevokeOne(serial *big.Int) error {
	list := make([]pkix.RevokedCertificate, 0)
	if oldList, err := p.GetCRL(); err == nil {
		list = oldList.TBSCertList.RevokedCertificates
	}
	caPairs, err := p.Storage.GetByCN("ca")
	if err != nil {
		return fmt.Errorf("can`t get ca certs for signing crl: %w", err)
	}
	sort.Slice(caPairs, func(i, j int) bool {
		return caPairs[i].Serial.Cmp(caPairs[j].Serial) == 1
	})
	caKey, caCert, err := caPairs[0].Decode()
	if err != nil {
		return fmt.Errorf("can`t decode ca certs for signing crl: %w", err)
	}
	list = append(list, pkix.RevokedCertificate{
		SerialNumber:   serial,
		RevocationTime: time.Now(),
	})
	crlBytes, err := caCert.CreateCRL(
		rand.Reader, caKey, removeDups(list), time.Now(), time.Now().Add(DefaultExpireYears*365*24*time.Hour))
	if err != nil {
		return fmt.Errorf("can`t create crl: %w", err)
	}
	crlPem := pem.EncodeToMemory(&pem.Block{
		Type:  PEMx509CRLBlock,
		Bytes: crlBytes,
	})
	err = p.crlHolder.Put(crlPem)
	if err != nil {
		return fmt.Errorf("can`t put new crl: %w", err)
	}
	return nil
}

// RevokeAllByCN revoke all pairs with common name
func (p *PKI) RevokeAllByCN(cn string) error {
	pairs, err := p.Storage.GetByCN(cn)
	if err != nil {
		return fmt.Errorf("can`t get pairs for revoke: %w", err)
	}
	for _, certPair := range pairs {
		err := p.RevokeOne(certPair.Serial)
		if err != nil {
			return fmt.Errorf("can`t revoke: %w", err)
		}
	}
	return nil
}

// IsRevoked return true if it`s revoked serial
func (p *PKI) IsRevoked(serial *big.Int) bool {
	revokedCerts, err := p.GetCRL()
	if err != nil {
		revokedCerts = &pkix.CertificateList{}
	}
	for _, cert := range revokedCerts.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

func removeDups(list []pkix.RevokedCertificate) []pkix.RevokedCertificate {
	encountered := map[int64]bool{}
	result := make([]pkix.RevokedCertificate, 0)
	for _, cert := range list {
		if !encountered[cert.SerialNumber.Int64()] {
			result = append(result, cert)
			encountered[cert.SerialNumber.Int64()] = true
		}
	}
	return result
}

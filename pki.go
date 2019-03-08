package easyrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"
	"math/big"
	"time"
)

type X509Pair struct {
	KeyPemBytes  []byte
	CertPemBytes []byte
	CN           string
	Serial       *big.Int
}

func (pair *X509Pair) Decode() (key *rsa.PrivateKey, cert *x509.Certificate, err error) {
	block, _ := pem.Decode([]byte(pair.KeyPemBytes))
	if block == nil {
		return nil, nil, errors.New("can`t parse key")
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "can`t parse key")
	}

	block, _ = pem.Decode([]byte(pair.CertPemBytes))
	if block == nil {
		return nil, nil, errors.New("can`t parse cert")
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "can`t parse cert")
	}
	return
}

func NewX509Pair(keyPemBytes []byte, certPemBytes []byte, CN string, serial *big.Int) *X509Pair {
	return &X509Pair{KeyPemBytes: keyPemBytes, CertPemBytes: certPemBytes, CN: CN, Serial: serial}
}

type PKI struct {
	Storage        KeyStorage
	serialProvider SerialProvider
	crlHolder      CRLHolder
	subjTemplate   pkix.Name
}

func NewPKI(storage KeyStorage, sp SerialProvider, subjTemplate pkix.Name) *PKI {
	return &PKI{Storage: storage, serialProvider: sp, subjTemplate: subjTemplate}
}

func (p *PKI) NewCa(save bool) (*X509Pair, error) {
	key, err := rsa.GenerateKey(rand.Reader, DefaultKeySizeBytes)
	if err != nil {
		return nil, xerrors.New("can`t generate key")
	}

	subj := p.subjTemplate
	subj.CommonName = "ca"

	serial, err := p.serialProvider.Next()
	if err != nil {
		return nil, err
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

	// Sign the certificate authority
	certificate, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, xerrors.New("can`t generate cert")
	}
	res := &X509Pair{
		KeyPemBytes: pem.EncodeToMemory(&pem.Block{
			Type:  PEMRSAPrivateKeyBlock,
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}),
		CertPemBytes: pem.EncodeToMemory(&pem.Block{
			Type:  PEMCertificateBlock,
			Bytes: certificate,
		}),
	}
	res = NewX509Pair(
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
	if save {
		err := p.Storage.Put(res)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (p *PKI) newCert(ca *X509Pair, server bool, cn string, save bool) (*X509Pair, error) {
	caKey, caCert, err := ca.Decode()
	if err != nil {
		return nil, errors.Wrap(err, "can`t parse ca pair: %v")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, "can`t create private key")
	}

	serial, err := p.serialProvider.Next()
	if err != nil {
		return nil, err
	}

	val, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 2}) // setting nsCertType to Client Type
	if err != nil {
		return nil, errors.Wrap(err, "can not marshal nsCertType")
	}

	now := time.Now()
	subj := p.subjTemplate
	subj.CommonName = cn
	tml := x509.Certificate{
		NotBefore:             now.Add(-10 * time.Minute).UTC(),
		NotAfter:              now.Add(time.Duration(24*365*99) * time.Hour).UTC(),
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

	if server {
		tml.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment
		tml.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		val, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x40}, BitLength: 2}) // setting nsCertType to Server Type
		if err != nil {
			return nil, errors.Wrap(err, "can not marshal nsCertType")
		}
		tml.ExtraExtensions[0].Id = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}
		tml.ExtraExtensions[0].Value = val
	}

	// Sign with CA's private key
	cert, err := x509.CreateCertificate(rand.Reader, &tml, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, errors.Wrap(err, "certificate cannot be created")
	}

	priKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  PEMRSAPrivateKeyBlock,
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  PEMCertificateBlock,
		Bytes: cert,
	})

	res := NewX509Pair(priKeyPem, certPem, cn, serial)
	if save {
		err := p.Storage.Put(res)
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

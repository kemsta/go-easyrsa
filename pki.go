package easyrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"golang.org/x/xerrors"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"time"
)

type X509Pair struct {
	KeyPemBytes  []byte
	CertPemBytes []byte
	CN           string
	Serial       *big.Int
}

func NewX509Pair(keyPemBytes []byte, certPemBytes []byte, CN string, serial *big.Int) *X509Pair {
	return &X509Pair{KeyPemBytes: keyPemBytes, CertPemBytes: certPemBytes, CN: CN, Serial: serial}
}

type PKI struct {
	KeyDir       string
	SubjTemplate pkix.Name
}

func NewPki(keyDir string, subjTemplate pkix.Name) (*PKI, error) {
	if keyDir == "" {
		return nil, xerrors.New("empty keydir")
	}
	return &PKI{KeyDir: keyDir, SubjTemplate: subjTemplate}, nil
}

func (p *PKI) NewCa(save bool) (*X509Pair, error) {
	key, err := rsa.GenerateKey(rand.Reader, DefaultKeySizeBytes)
	if err != nil {
		return nil, xerrors.New("can`t generate key")
	}

	subj := p.SubjTemplate
	subj.CommonName = "ca"

	serial, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
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
	if save {
		err := p.savePair("ca", res)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (p *PKI) savePair(cn string, pair *X509Pair) error {
	err := ioutil.WriteFile(filepath.Join(p.KeyDir, fmt.Sprintf("%s.key", cn)), pair.KeyPemBytes, 0600)
	if err != nil {
		return xerrors.New("can`t write key")
	}
	err = ioutil.WriteFile(filepath.Join(p.KeyDir, fmt.Sprintf("%s.crt", cn)), pair.CertPemBytes, 0600)
	if err != nil {
		return xerrors.New("can`t write crt")
	}
	return nil
}

func (p *PKI) readPair(cn string) (*X509Pair, error) {
	var err error
	pair := &X509Pair{}
	pair.KeyPemBytes, err = ioutil.ReadFile(filepath.Join(p.KeyDir, fmt.Sprintf("%s.key", cn)))
	if err != nil {
		return nil, xerrors.New("can`t read key")
	}
	pair.CertPemBytes, err = ioutil.ReadFile(filepath.Join(p.KeyDir, fmt.Sprintf("%s.crt", cn)))
	if err != nil {
		return nil, xerrors.New("can`t read key")
	}
	return pair, nil
}

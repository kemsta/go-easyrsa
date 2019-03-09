package easyrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"sort"
	"time"

	"github.com/pkg/errors"
)

// x509 pair representation
type X509Pair struct {
	KeyPemBytes  []byte   // pem encoded rsa.PrivateKey bytes
	CertPemBytes []byte   // pem encoded x509.Certificate bytes
	CN           string   // common name
	Serial       *big.Int // serial number
}

// decode pem bytes to rsa.PrivateKey and x509.Certificate
func (pair *X509Pair) Decode() (key *rsa.PrivateKey, cert *x509.Certificate, err error) {
	block, _ := pem.Decode(pair.KeyPemBytes)
	if block == nil {
		return nil, nil, errors.New("can`t parse key")
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "can`t parse key")
	}

	block, _ = pem.Decode(pair.CertPemBytes)
	if block == nil {
		return nil, nil, errors.New("can`t parse cert")
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "can`t parse cert")
	}
	return
}

// create new X509Pair
func NewX509Pair(keyPemBytes []byte, certPemBytes []byte, CN string, serial *big.Int) *X509Pair {
	return &X509Pair{KeyPemBytes: keyPemBytes, CertPemBytes: certPemBytes, CN: CN, Serial: serial}
}

type PKI struct {
	Storage        KeyStorage
	serialProvider SerialProvider
	crlHolder      CRLHolder
	subjTemplate   pkix.Name
}

func NewPKI(storage KeyStorage, sp SerialProvider, crlHolder CRLHolder, subjTemplate pkix.Name) *PKI {
	return &PKI{Storage: storage, serialProvider: sp, crlHolder: crlHolder, subjTemplate: subjTemplate}
}

func (p *PKI) NewCa() (*X509Pair, error) {
	key, err := rsa.GenerateKey(rand.Reader, DefaultKeySizeBytes)
	if err != nil {
		return nil, errors.New("can`t generate key")
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
		return nil, errors.New("can`t generate cert")
	}

	res := NewX509Pair(
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
		return nil, err
	}
	return res, nil
}

func (p *PKI) NewCert(cn string, server bool) (*X509Pair, error) {
	caPair, err := p.GetLastCA()
	if err != nil {
		return nil, errors.Wrap(err, "can`t get ca pair")
	}
	caKey, caCert, err := caPair.Decode()
	if err != nil {
		return nil, errors.Wrap(err, "can`t parse ca pair")
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

	err = p.Storage.Put(res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (p *PKI) GetCRL() (*pkix.CertificateList, error) {
	return p.crlHolder.Get()
}

func (p *PKI) GetLastCA() (*X509Pair, error) {
	return p.GetLastCert("ca")
}

func (p *PKI) GetLastCert(cn string) (*X509Pair, error) {
	pairs, err := p.Storage.GetByCN(cn)
	if err != nil {
		return nil, errors.Wrap(err, "can`t get cert")
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Serial.Cmp(pairs[j].Serial) == 1
	})
	return pairs[0], nil
}

func (p *PKI) RevokeOne(serial *big.Int) error {
	list := make([]pkix.RevokedCertificate, 0)
	if oldList, err := p.GetCRL(); err == nil {
		list = oldList.TBSCertList.RevokedCertificates
	}
	caPairs, err := p.Storage.GetByCN("ca")
	if err != nil {
		return errors.Wrap(err, "can`t get ca certs for signing crl")
	}
	sort.Slice(caPairs, func(i, j int) bool {
		return caPairs[i].Serial.Cmp(caPairs[j].Serial) == 1
	})
	caKey, caCert, err := caPairs[0].Decode()
	if err != nil {
		return errors.Wrap(err, "can`t decode ca certs for signing crl")
	}
	list = append(list, pkix.RevokedCertificate{
		SerialNumber:   serial,
		RevocationTime: time.Now(),
	})
	crlBytes, err := caCert.CreateCRL(
		rand.Reader, caKey, removeDups(list), time.Now(), time.Now().Add(99*365*24*time.Hour))
	if err != nil {
		return errors.Wrap(err, "can`t create crl")
	}
	crlPem := pem.EncodeToMemory(&pem.Block{
		Type:  PEMx509CRLBlock,
		Bytes: crlBytes,
	})
	err = p.crlHolder.Put(crlPem)
	if err != nil {
		return errors.Wrap(err, "can`t put new crl")
	}
	return nil
}

func (p *PKI) RevokeAllByCN(cn string) error {
	pairs, err := p.Storage.GetByCN(cn)
	if err != nil {
		return errors.Wrap(err, "can`t get pairs for revoke")
	}
	for _, pair := range pairs {
		err := p.RevokeOne(pair.Serial)
		if err != nil {
			return errors.Wrap(err, "can`t revoke")
		}
	}
	return nil
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

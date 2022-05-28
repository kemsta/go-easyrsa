package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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
	PEMx509CRLBlock     string = "X509 CRL" // pem block header for CRL
	DefaultKeySizeBytes int    = 2048       // default key size in bytes
	DefaultExpireYears         = 1          // default expire time for certs
)

// PKI is a main struct for private key infrastructure
type PKI struct {
	storage        KeyStorage
	serialProvider SerialProvider
	crlHolder      CRLHolder
	subjTemplate   pkix.Name
}

// NewPKI PKI struct "constructor"
func NewPKI(storage KeyStorage, sp SerialProvider, crlHolder CRLHolder, subjTemplate pkix.Name) *PKI {
	return &PKI{storage: storage, serialProvider: sp, crlHolder: crlHolder, subjTemplate: subjTemplate}
}

// InitPKI initialize default pki with default file storages
// defaultVars will be used for constructing every certificate as a template
func InitPKI(pkiDir string, defaultVars *pkix.Name) (*PKI, error) {
	if defaultVars == nil {
		defaultVars = &pkix.Name{}
	}
	pki := NewPKI(fsStorage.NewDirKeyStorage(pkiDir),
		fsStorage.NewFileSerialProvider(path.Join(pkiDir, "serial")),
		fsStorage.NewFileCRLHolder(path.Join(pkiDir, "crl.pem")),
		*defaultVars)

	if _, err := os.Stat(pkiDir); os.IsNotExist(err) {
		if err := os.MkdirAll(pkiDir, 0750); err != nil {
			return nil, fmt.Errorf("can't create %v: %w", pkiDir, err)
		}
	}
	return pki, nil
}

// NewCa create new version self-signed CA pair
// opts are functional parameters that will be applied on the template before cert creating
func (p *PKI) NewCa(keySizeBytes int, opts ...CertificateOption) (*pair.X509Pair, error) {
	opts = append([]CertificateOption{CA(), CN("ca")}, opts...)
	return p.NewCert(keySizeBytes, true, opts...)
}

func (p *PKI) NewClientCert(name string, keySizeBytes int, opts ...CertificateOption) (*pair.X509Pair, error) {
	opts = append([]CertificateOption{Client(), CN(name)}, opts...)
	return p.NewCert(keySizeBytes, false, opts...)
}

func (p *PKI) NewServerCert(name string, keySizeBytes int, opts ...CertificateOption) (*pair.X509Pair, error) {
	opts = append([]CertificateOption{Server(), CN(name)}, opts...)
	return p.NewCert(keySizeBytes, false, opts...)
}

func (p *PKI) createRequest(privateKey any, opts ...RequestOption) (*x509.CertificateRequest, error) {
	sigType := x509.UnknownSignatureAlgorithm
	if privateKey, ok := privateKey.(*rsa.PrivateKey); ok {
		keySize := privateKey.N.BitLen()
		switch {
		case keySize >= 4096:
			sigType = x509.SHA512WithRSA
		case keySize >= 3072:
			sigType = x509.SHA384WithRSA
		default:
			sigType = x509.SHA256WithRSA
		}
	}

	template := x509.CertificateRequest{
		Subject:            p.subjTemplate,
		SignatureAlgorithm: sigType,
	}
	applyRequestOptions(opts, &template)

	request, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("can't create request: %w", err)
	}

	certificateRequest, err := x509.ParseCertificateRequest(request)
	if err != nil {
		return nil, fmt.Errorf("can't parse request: %w", err)
	}
	return certificateRequest, nil
}

func (p *PKI) createCert(private any, request *x509.CertificateRequest, parent *x509.Certificate, options ...CertificateOption) (*x509.Certificate, error) {
	serial, err := p.serialProvider.Next()
	if err != nil {
		return nil, fmt.Errorf("can`t get next serial: %w", err)
	}

	now := time.Now()

	template := &x509.Certificate{
		Subject:               request.Subject,
		PublicKeyAlgorithm:    request.PublicKeyAlgorithm,
		PublicKey:             request.PublicKey,
		SignatureAlgorithm:    request.SignatureAlgorithm,
		SerialNumber:          serial,
		NotBefore:             now.Add(-10 * time.Minute).UTC(),
		NotAfter:              now.Add(time.Duration(24*365*DefaultExpireYears) * time.Hour).UTC(),
		BasicConstraintsValid: true,
	}

	applyCertOptions(options, template)

	if parent == nil {
		parent = template
	}

	if template.Subject.CommonName == "" {
		return nil, errors.New("certificate CN is obligatory")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, request.PublicKey, private)
	if err != nil {
		return nil, fmt.Errorf("certificate cannot be created: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("certificate cannot be parsed: %w", err)
	}
	return cert, nil
}

// NewCert generate new pair signed by last CA key
func (p *PKI) NewCert(keySizeBytes int, selfsigned bool, opts ...CertificateOption) (*pair.X509Pair, error) {
	if keySizeBytes == 0 {
		keySizeBytes = DefaultKeySizeBytes
	}
	certKey, err := rsa.GenerateKey(rand.Reader, DefaultKeySizeBytes)
	if err != nil {
		return nil, fmt.Errorf("can`t generate key: %w", err)
	}

	request, err := p.createRequest(certKey)
	if err != nil {
		return nil, fmt.Errorf("can`t generate request for ca cert: %w", err)
	}

	var caKey *rsa.PrivateKey
	var caCert *x509.Certificate
	if selfsigned {
		caKey = certKey
		caCert = nil
	} else {
		caPair, err := p.GetLastCA()
		if err != nil {
			return nil, fmt.Errorf("can`t get ca pair: %w", err)
		}
		caKey, caCert, err = caPair.Decode()
		if err != nil {
			return nil, fmt.Errorf("can`t parse ca pair: %w", err)
		}
	}

	cert, err := p.createCert(caKey, request, caCert, opts...)
	if err != nil {
		return nil, fmt.Errorf("can`t create ca cert: %w", err)
	}

	res := pair.NewX509Pair(certKey, cert)

	err = p.storage.Put(res)
	if err != nil {
		return nil, fmt.Errorf("can't put generated cert into storage: %w", err)
	}
	return res, nil
}

// GetCRL return current revoke list
func (p *PKI) GetCRL() (*pkix.CertificateList, error) {
	return p.crlHolder.Get()
}

// GetLastCA return last CA pair
func (p *PKI) GetLastCA() (*pair.X509Pair, error) {
	return p.storage.GetLastByCn("ca")
}

// RevokeOne revoke one pair with serial
func (p *PKI) RevokeOne(serial *big.Int) error {
	list := make([]pkix.RevokedCertificate, 0)
	if oldList, err := p.GetCRL(); err == nil {
		list = oldList.TBSCertList.RevokedCertificates
	}
	caPairs, err := p.storage.GetByCN("ca")
	if err != nil {
		return fmt.Errorf("can`t get ca certs for signing crl: %w", err)
	}
	sort.Slice(caPairs, func(i, j int) bool {
		return caPairs[i].Serial().Cmp(caPairs[j].Serial()) == 1
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
	pairs, err := p.storage.GetByCN(cn)
	if err != nil {
		return fmt.Errorf("can`t get pairs for revoke: %w", err)
	}
	for _, certPair := range pairs {
		err := p.RevokeOne(certPair.Serial())
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

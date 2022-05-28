package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"time"
)

type CertificateOption func(*x509.Certificate)
type RequestOption func(request *x509.CertificateRequest)

func applyCertOptions(options []CertificateOption, cert *x509.Certificate) {
	for _, option := range options {
		option(cert)
	}
}

func applyRequestOptions(options []RequestOption, cert *x509.CertificateRequest) {
	for _, option := range options {
		option(cert)
	}
}

func Server() CertificateOption {
	return func(certificate *x509.Certificate) {
		certificate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment
		certificate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if certificate.ExtraExtensions == nil {
			certificate.ExtraExtensions = []pkix.Extension{}
		}
		val, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{0x40}, BitLength: 2}) // setting nsCertType to Server Type
		if certificate.ExtraExtensions == nil {
			certificate.ExtraExtensions = []pkix.Extension{}
		}
		certificate.ExtraExtensions = append(certificate.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}, Value: val})
	}
}

func ExcludedDNSDomains(names []string) CertificateOption {
	return func(certificate *x509.Certificate) {
		certificate.ExcludedDNSDomains = names
	}
}

func NotAfter(time time.Time) CertificateOption {
	return func(certificate *x509.Certificate) {
		certificate.NotAfter = time
	}
}

func CA() CertificateOption {
	return func(certificate *x509.Certificate) {
		certificate.IsCA = true
		certificate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
}

func Client() CertificateOption {
	return func(certificate *x509.Certificate) {
		val, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 2})
		certificate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
		certificate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		certificate.ExtraExtensions = []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1},
				Value: val,
			},
		}
	}
}

func IPAddresses(ips []net.IP) CertificateOption {
	return func(certificate *x509.Certificate) {
		certificate.IPAddresses = ips

	}
}

func DNSNames(names []string) CertificateOption {
	return func(certificate *x509.Certificate) {
		certificate.DNSNames = names
	}
}

func CN(cn string) CertificateOption {
	return func(certificate *x509.Certificate) {
		certificate.Subject.CommonName = cn
	}
}

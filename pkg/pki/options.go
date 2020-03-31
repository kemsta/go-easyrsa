package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"time"
)

type Option func(*x509.Certificate)

func Apply(options []Option, cert *x509.Certificate) {
	for _, option := range options {
		option(cert)
	}
}

func CN(cn string) Option {
	return func(certificate *x509.Certificate) {
		certificate.Subject.CommonName = cn
	}
}

func Server() Option {
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

func DNSNames(names []string) Option {
	return func(certificate *x509.Certificate) {
		certificate.DNSNames = names
	}
}

func IPAddresses(ips []net.IP) Option {
	return func(certificate *x509.Certificate) {
		certificate.IPAddresses = ips
	}
}

func ExcludedDNSDomains(names []string) Option {
	return func(certificate *x509.Certificate) {
		certificate.ExcludedDNSDomains = names
	}
}

func NotAfter(time time.Time) Option {
	return func(certificate *x509.Certificate) {
		certificate.NotAfter = time
	}
}

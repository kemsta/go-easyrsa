package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"net/url"
	"reflect"
	"time"

	"github.com/kemsta/go-easyrsa/v2/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/v2/crypto"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// BuildClientFull generates a client key and issues a signed client certificate.
func (p *PKI) BuildClientFull(name string, opts ...Option) (*cert.Pair, error) {
	if !p.bound() {
		return withUpdate(p, func(bound *PKI) (*cert.Pair, error) { return bound.BuildClientFull(name, opts...) })
	}
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
	if _, err := p.GenReq(name, opts...); err != nil {
		return nil, err
	}
	pair, err := p.SignReq(name, cert.CertTypeClient, opts...)
	if err != nil {
		_ = p.storage.DeleteByName(name) // best-effort: remove key stored by GenReq
		return nil, err
	}
	return pair, nil
}

// BuildServerFull generates a server key and issues a signed server certificate.
func (p *PKI) BuildServerFull(name string, opts ...Option) (*cert.Pair, error) {
	if !p.bound() {
		return withUpdate(p, func(bound *PKI) (*cert.Pair, error) { return bound.BuildServerFull(name, opts...) })
	}
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
	if _, err := p.GenReq(name, opts...); err != nil {
		return nil, err
	}
	pair, err := p.SignReq(name, cert.CertTypeServer, opts...)
	if err != nil {
		_ = p.storage.DeleteByName(name) // best-effort: remove key stored by GenReq
		return nil, err
	}
	return pair, nil
}

// BuildServerClientFull generates a key and issues a combined server+client certificate.
func (p *PKI) BuildServerClientFull(name string, opts ...Option) (*cert.Pair, error) {
	if !p.bound() {
		return withUpdate(p, func(bound *PKI) (*cert.Pair, error) {
			return bound.BuildServerClientFull(name, opts...)
		})
	}
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
	if _, err := p.GenReq(name, opts...); err != nil {
		return nil, err
	}
	pair, err := p.SignReq(name, cert.CertTypeServerClient, opts...)
	if err != nil {
		_ = p.storage.DeleteByName(name) // best-effort: remove key stored by GenReq
		return nil, err
	}
	return pair, nil
}

// Renew renews a certificate by name, retaining the existing private key.
func (p *PKI) Renew(name string, opts ...Option) (*cert.Pair, error) {
	if !p.bound() {
		return withUpdate(p, func(bound *PKI) (*cert.Pair, error) { return bound.Renew(name, opts...) })
	}
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
	o := applyOptions(opts)

	existing, err := p.storage.GetLastByName(name)
	if err != nil {
		return nil, err
	}
	oldCert, err := validateLifecycleCertificate(existing)
	if err != nil {
		return nil, err
	}
	oldSerial := oldCert.SerialNumber // capture before generating the new cert

	caPair, err := p.storage.GetLastByName(p.config.CAName)
	if err != nil {
		return nil, err
	}
	caKey, err := pkicrypto.UnmarshalPrivateKey(caPair.KeyPEM, p.config.CAPassphrase)
	if err != nil {
		return nil, err
	}
	caCert, err := caPair.Certificate()
	if err != nil {
		return nil, err
	}

	serial, err := p.nextSerial()
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	if !o.notBefore.IsZero() {
		notBefore = o.notBefore
	}
	notAfter := addExactDays(notBefore, p.config.DefaultDays)
	if !o.notAfter.IsZero() {
		notAfter = o.notAfter
	}

	template := &x509.Certificate{
		SerialNumber:                serial,
		SignatureAlgorithm:          oldCert.SignatureAlgorithm,
		Subject:                     oldCert.Subject,
		NotBefore:                   notBefore,
		NotAfter:                    notAfter,
		KeyUsage:                    oldCert.KeyUsage,
		ExtKeyUsage:                 append([]x509.ExtKeyUsage(nil), oldCert.ExtKeyUsage...),
		UnknownExtKeyUsage:          append([]asn1.ObjectIdentifier(nil), oldCert.UnknownExtKeyUsage...),
		BasicConstraintsValid:       oldCert.BasicConstraintsValid,
		IsCA:                        oldCert.IsCA,
		MaxPathLen:                  oldCert.MaxPathLen,
		MaxPathLenZero:              oldCert.MaxPathLenZero,
		DNSNames:                    append([]string(nil), oldCert.DNSNames...),
		IPAddresses:                 cloneIPAddresses(oldCert.IPAddresses),
		EmailAddresses:              append([]string(nil), oldCert.EmailAddresses...),
		URIs:                        cloneURLs(oldCert.URIs),
		SubjectKeyId:                append([]byte(nil), oldCert.SubjectKeyId...),
		OCSPServer:                  append([]string(nil), oldCert.OCSPServer...),
		IssuingCertificateURL:       append([]string(nil), oldCert.IssuingCertificateURL...),
		PermittedDNSDomainsCritical: oldCert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         append([]string(nil), oldCert.PermittedDNSDomains...),
		ExcludedDNSDomains:          append([]string(nil), oldCert.ExcludedDNSDomains...),
		PermittedIPRanges:           cloneIPNetworks(oldCert.PermittedIPRanges),
		ExcludedIPRanges:            cloneIPNetworks(oldCert.ExcludedIPRanges),
		PermittedEmailAddresses:     append([]string(nil), oldCert.PermittedEmailAddresses...),
		ExcludedEmailAddresses:      append([]string(nil), oldCert.ExcludedEmailAddresses...),
		PermittedURIDomains:         append([]string(nil), oldCert.PermittedURIDomains...),
		ExcludedURIDomains:          append([]string(nil), oldCert.ExcludedURIDomains...),
		CRLDistributionPoints:       append([]string(nil), oldCert.CRLDistributionPoints...),
		PolicyIdentifiers:           cloneObjectIdentifiers(oldCert.PolicyIdentifiers),
		Policies:                    append([]x509.OID(nil), oldCert.Policies...),
		InhibitAnyPolicy:            oldCert.InhibitAnyPolicy,
		InhibitAnyPolicyZero:        oldCert.InhibitAnyPolicyZero,
		InhibitPolicyMapping:        oldCert.InhibitPolicyMapping,
		InhibitPolicyMappingZero:    oldCert.InhibitPolicyMappingZero,
		RequireExplicitPolicy:       oldCert.RequireExplicitPolicy,
		RequireExplicitPolicyZero:   oldCert.RequireExplicitPolicyZero,
		PolicyMappings:              append([]x509.PolicyMapping(nil), oldCert.PolicyMappings...),
		AuthorityKeyId:              append([]byte(nil), caCert.SubjectKeyId...),
	}

	for _, mod := range o.certModifiers {
		mod(template)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, preservedProfileExtensions(oldCert, template)...)

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, oldCert.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPEM := pemEncodeCert(certDER)

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	pair := &cert.Pair{Name: name, CertPEM: certPEM, KeyPEM: existing.KeyPEM}
	if err := p.lifecycle.MoveIssuedToRenewed(name, oldSerial); err != nil {
		return nil, err
	}
	if err := p.removeDerivedArtifacts(name); err != nil {
		return nil, err
	}
	if err := p.storage.Put(pair); err != nil {
		return nil, err
	}
	if err := p.index.RecordAndUpdate(storage.IndexEntry{
		Status:    storage.StatusValid,
		ExpiresAt: parsedCert.NotAfter,
		Serial:    parsedCert.SerialNumber,
		Subject:   parsedCert.Subject,
	}, oldSerial, storage.StatusExpired, time.Time{}, 0); err != nil {
		return nil, err
	}

	return pair, nil
}

// ExpireCert forces a certificate into expired state in the index.
var (
	oidExtensionSubjectKeyID        = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionBasicConstraints    = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionNameConstraints     = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidExtensionCRLDistribution     = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtensionCertificatePolicy   = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtensionPolicyMappings      = asn1.ObjectIdentifier{2, 5, 29, 33}
	oidExtensionAuthorityKeyID      = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtensionPolicyConstraints   = asn1.ObjectIdentifier{2, 5, 29, 36}
	oidExtensionExtendedKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionInhibitAnyPolicy    = asn1.ObjectIdentifier{2, 5, 29, 54}
	oidExtensionAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

func preservedProfileExtensions(oldCertificate, template *x509.Certificate) []pkix.Extension {
	preserve := map[string]bool{
		oidExtensionSubjectKeyID.String():   bytes.Equal(template.SubjectKeyId, oldCertificate.SubjectKeyId),
		oidExtensionAuthorityKeyID.String(): bytes.Equal(template.AuthorityKeyId, oldCertificate.AuthorityKeyId),
		oidExtensionKeyUsage.String():       template.KeyUsage == oldCertificate.KeyUsage,
		oidExtensionSubjectAltName.String(): reflect.DeepEqual(template.DNSNames, oldCertificate.DNSNames) &&
			reflect.DeepEqual(template.IPAddresses, oldCertificate.IPAddresses) &&
			reflect.DeepEqual(template.EmailAddresses, oldCertificate.EmailAddresses) &&
			reflect.DeepEqual(template.URIs, oldCertificate.URIs),
		oidExtensionBasicConstraints.String(): template.BasicConstraintsValid == oldCertificate.BasicConstraintsValid &&
			template.IsCA == oldCertificate.IsCA && template.MaxPathLen == oldCertificate.MaxPathLen &&
			template.MaxPathLenZero == oldCertificate.MaxPathLenZero,
		oidExtensionExtendedKeyUsage.String(): reflect.DeepEqual(template.ExtKeyUsage, oldCertificate.ExtKeyUsage) &&
			reflect.DeepEqual(template.UnknownExtKeyUsage, oldCertificate.UnknownExtKeyUsage),
		oidExtensionAuthorityInfoAccess.String(): reflect.DeepEqual(template.OCSPServer, oldCertificate.OCSPServer) &&
			reflect.DeepEqual(template.IssuingCertificateURL, oldCertificate.IssuingCertificateURL),
		oidExtensionNameConstraints.String(): template.PermittedDNSDomainsCritical == oldCertificate.PermittedDNSDomainsCritical &&
			reflect.DeepEqual(template.PermittedDNSDomains, oldCertificate.PermittedDNSDomains) &&
			reflect.DeepEqual(template.ExcludedDNSDomains, oldCertificate.ExcludedDNSDomains) &&
			reflect.DeepEqual(template.PermittedIPRanges, oldCertificate.PermittedIPRanges) &&
			reflect.DeepEqual(template.ExcludedIPRanges, oldCertificate.ExcludedIPRanges) &&
			reflect.DeepEqual(template.PermittedEmailAddresses, oldCertificate.PermittedEmailAddresses) &&
			reflect.DeepEqual(template.ExcludedEmailAddresses, oldCertificate.ExcludedEmailAddresses) &&
			reflect.DeepEqual(template.PermittedURIDomains, oldCertificate.PermittedURIDomains) &&
			reflect.DeepEqual(template.ExcludedURIDomains, oldCertificate.ExcludedURIDomains),
		oidExtensionCRLDistribution.String(): reflect.DeepEqual(template.CRLDistributionPoints, oldCertificate.CRLDistributionPoints),
		oidExtensionCertificatePolicy.String(): reflect.DeepEqual(template.PolicyIdentifiers, oldCertificate.PolicyIdentifiers) &&
			reflect.DeepEqual(template.Policies, oldCertificate.Policies),
		oidExtensionInhibitAnyPolicy.String(): template.InhibitAnyPolicy == oldCertificate.InhibitAnyPolicy &&
			template.InhibitAnyPolicyZero == oldCertificate.InhibitAnyPolicyZero,
		oidExtensionPolicyConstraints.String(): template.InhibitPolicyMapping == oldCertificate.InhibitPolicyMapping &&
			template.InhibitPolicyMappingZero == oldCertificate.InhibitPolicyMappingZero &&
			template.RequireExplicitPolicy == oldCertificate.RequireExplicitPolicy &&
			template.RequireExplicitPolicyZero == oldCertificate.RequireExplicitPolicyZero,
		oidExtensionPolicyMappings.String(): reflect.DeepEqual(template.PolicyMappings, oldCertificate.PolicyMappings),
	}
	overridden := make(map[string]bool, len(template.ExtraExtensions))
	for _, extension := range template.ExtraExtensions {
		overridden[extension.Id.String()] = true
	}
	var extensions []pkix.Extension
	for _, extension := range oldCertificate.Extensions {
		oid := extension.Id.String()
		if overridden[oid] {
			continue
		}
		if preserveKnown, known := preserve[oid]; known && !preserveKnown {
			continue
		}
		extension.Id = append(asn1.ObjectIdentifier(nil), extension.Id...)
		extension.Value = append([]byte(nil), extension.Value...)
		extensions = append(extensions, extension)
	}
	return extensions
}

func cloneIPAddresses(addresses []net.IP) []net.IP {
	if addresses == nil {
		return nil
	}
	cloned := make([]net.IP, len(addresses))
	for i := range addresses {
		cloned[i] = append(net.IP(nil), addresses[i]...)
	}
	return cloned
}

func cloneIPNetworks(networks []*net.IPNet) []*net.IPNet {
	if networks == nil {
		return nil
	}
	cloned := make([]*net.IPNet, len(networks))
	for i, network := range networks {
		if network != nil {
			cloned[i] = &net.IPNet{
				IP:   append(net.IP(nil), network.IP...),
				Mask: append(net.IPMask(nil), network.Mask...),
			}
		}
	}
	return cloned
}

func cloneObjectIdentifiers(identifiers []asn1.ObjectIdentifier) []asn1.ObjectIdentifier {
	if identifiers == nil {
		return nil
	}
	cloned := make([]asn1.ObjectIdentifier, len(identifiers))
	for i := range identifiers {
		cloned[i] = append(asn1.ObjectIdentifier(nil), identifiers[i]...)
	}
	return cloned
}

func cloneURLs(urls []*url.URL) []*url.URL {
	if urls == nil {
		return nil
	}
	cloned := make([]*url.URL, len(urls))
	for i, value := range urls {
		if value != nil {
			copy := *value
			cloned[i] = &copy
		}
	}
	return cloned
}

func (p *PKI) ExpireCert(name string) error {
	if !p.bound() {
		return withUpdateError(p, func(bound *PKI) error { return bound.ExpireCert(name) })
	}
	if err := validateEntityName(name); err != nil {
		return err
	}
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return err
	}
	serial, err := pair.Serial()
	if err != nil {
		return err
	}
	return p.index.Update(serial, storage.StatusExpired, time.Time{}, 0)
}

package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
)

// RequestInfo is the typed, presentation-neutral result of CSR inspection.
type RequestInfo struct {
	Name               string
	Subject            pkix.RDNSequence
	DNSNames           []string
	IPAddresses        []net.IP
	EmailAddresses     []string
	PublicKey          string
	SignatureAlgorithm x509.SignatureAlgorithm
}

// Info parses the CSR structure without verifying its signature and returns a
// recursively independent inspection result.
func (c *CSR) Info() (*RequestInfo, error) {
	request, err := c.Request()
	if err != nil {
		return nil, err
	}
	var subject pkix.RDNSequence
	rest, err := asn1.Unmarshal(request.RawSubject, &subject)
	if err != nil {
		return nil, fmt.Errorf("cert: parse request subject: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("cert: trailing data in request subject")
	}
	return &RequestInfo{
		Name:               c.Name,
		Subject:            cloneRDNSequence(subject),
		DNSNames:           append([]string(nil), request.DNSNames...),
		IPAddresses:        cloneRequestIPs(request.IPAddresses),
		EmailAddresses:     append([]string(nil), request.EmailAddresses...),
		PublicKey:          publicKeyDescription(request.PublicKey),
		SignatureAlgorithm: request.SignatureAlgorithm,
	}, nil
}

func publicKeyDescription(publicKey any) string {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", key.N.BitLen())
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.Params() == nil {
			return "ECDSA-unknown"
		}
		return "ECDSA-" + key.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", publicKey)
	}
}

func cloneRequestIPs(addresses []net.IP) []net.IP {
	if addresses == nil {
		return nil
	}
	cloned := make([]net.IP, len(addresses))
	for i := range addresses {
		cloned[i] = append(net.IP(nil), addresses[i]...)
	}
	return cloned
}

func cloneRDNSequence(sequence pkix.RDNSequence) pkix.RDNSequence {
	cloned := make(pkix.RDNSequence, len(sequence))
	for i, set := range sequence {
		cloned[i] = make([]pkix.AttributeTypeAndValue, len(set))
		for j, attribute := range set {
			attribute.Type = append(asn1.ObjectIdentifier(nil), attribute.Type...)
			attribute.Value = cloneRequestAttribute(attribute.Value)
			cloned[i][j] = attribute
		}
	}
	return cloned
}

func cloneRequestAttribute(value any) any {
	switch value := value.(type) {
	case []byte:
		return append([]byte(nil), value...)
	case asn1.ObjectIdentifier:
		return append(asn1.ObjectIdentifier(nil), value...)
	case asn1.RawValue:
		value.Bytes = append([]byte(nil), value.Bytes...)
		value.FullBytes = append([]byte(nil), value.FullBytes...)
		return value
	case asn1.BitString:
		value.Bytes = append([]byte(nil), value.Bytes...)
		return value
	case []any:
		cloned := make([]any, len(value))
		for i := range value {
			cloned[i] = cloneRequestAttribute(value[i])
		}
		return cloned
	default:
		return value
	}
}

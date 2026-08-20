package pki

import (
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

// DNForm selects the input structure parsed by DisplayDN.
type DNForm string

const (
	DNFormX509    DNForm = "x509"
	DNFormRequest DNForm = "req"
)

// DisplayDN parses the raw subject from a certificate or request file while
// preserving RDN order, repeated attributes, multi-valued sets, and unknown
// OIDs. The input must resolve to a regular file.
func (p *PKI) DisplayDN(form DNForm, name string) (pkix.RDNSequence, error) {
	if form != DNFormX509 && form != DNFormRequest {
		return nil, fmt.Errorf("pki: unsupported DN form %q", form)
	}
	data, err := readRequiredRegularPath(name)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("pki: failed to decode PEM input")
	}
	var rawSubject []byte
	switch form {
	case DNFormX509:
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse certificate: %w", err)
		}
		rawSubject = certificate.RawSubject
	case DNFormRequest:
		request, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse certificate request: %w", err)
		}
		rawSubject = request.RawSubject
	}
	var sequence pkix.RDNSequence
	rest, err := asn1.Unmarshal(rawSubject, &sequence)
	if err != nil {
		return nil, fmt.Errorf("pki: parse subject DN: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("pki: trailing data in subject DN")
	}
	return cloneDNSequence(sequence), nil
}

// Rand streams count cryptographically random bytes as lowercase hexadecimal
// followed by one newline.
func (p *PKI) Rand(count int64, destination io.Writer) error {
	if count <= 0 {
		return errors.New("pki: random byte count must be positive")
	}
	if destination == nil {
		return errors.New("pki: random destination must not be nil")
	}
	source := io.Reader(cryptorand.Reader)
	if p != nil && p.random != nil {
		source = p.random
	}
	written, err := io.CopyN(hex.NewEncoder(destination), source, count)
	if err != nil {
		return fmt.Errorf("pki: generate random bytes: %w", err)
	}
	if written != count {
		return fmt.Errorf("pki: generated %d random bytes, expected %d", written, count)
	}
	newlineBytes, err := io.WriteString(destination, "\n")
	if err != nil {
		return fmt.Errorf("pki: write random output: %w", err)
	}
	if newlineBytes != 1 {
		return fmt.Errorf("pki: write random output: %w", io.ErrShortWrite)
	}
	return nil
}

// Serial is the explicit method for Easy-RSA's serial command.
func (p *PKI) Serial(serial *big.Int) (*storage.IndexEntry, error) {
	return p.CheckSerial(serial)
}

func cloneDNSequence(sequence pkix.RDNSequence) pkix.RDNSequence {
	cloned := make(pkix.RDNSequence, len(sequence))
	for i, set := range sequence {
		cloned[i] = make([]pkix.AttributeTypeAndValue, len(set))
		for j, attribute := range set {
			attribute.Type = append(asn1.ObjectIdentifier(nil), attribute.Type...)
			attribute.Value = cloneDNValue(attribute.Value)
			cloned[i][j] = attribute
		}
	}
	return cloned
}

func cloneDNValue(value any) any {
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
			cloned[i] = cloneDNValue(value[i])
		}
		return cloned
	default:
		return value
	}
}

package cert_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
)

func TestRequestInfoReturnsTypedDeepCopyWithoutSignatureVerification(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	sharedBits := []byte{0xaa, 0xbb}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "client",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{1, 2, 3}},
				{Type: asn1.ObjectIdentifier{1, 2, 3, 5}, Value: asn1.BitString{Bytes: sharedBits, BitLength: 16}},
				{Type: asn1.ObjectIdentifier{1, 2, 3, 6}, Value: asn1.BitString{Bytes: sharedBits, BitLength: 16}},
			},
		},
		DNSNames:       []string{"client.example.test"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10")},
		EmailAddresses: []string{"client@example.test"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	// Damage only the signature bytes. Structural inspection must still work.
	der[len(der)-1] ^= 0xff
	request := &cert.CSR{
		Name:   "storage-name",
		CSRPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
	}

	info, err := request.Info()
	require.NoError(t, err)
	require.Equal(t, "storage-name", info.Name)
	require.Equal(t, []string{"client.example.test"}, info.DNSNames)
	require.Equal(t, "192.0.2.10", info.IPAddresses[0].String())
	require.Equal(t, []string{"client@example.test"}, info.EmailAddresses)
	require.Equal(t, "RSA-1024", info.PublicKey)
	require.Equal(t, x509.SHA256WithRSA, info.SignatureAlgorithm)

	var bitStrings []asn1.BitString
	for _, set := range info.Subject {
		for _, attribute := range set {
			if value, ok := attribute.Value.(asn1.BitString); ok {
				bitStrings = append(bitStrings, value)
			}
		}
	}
	require.Len(t, bitStrings, 2)
	bitStrings[0].Bytes[0] = 0
	require.Equal(t, byte(0xaa), bitStrings[1].Bytes[0])
	info.DNSNames[0] = "mutated"
	info.IPAddresses[0][0] ^= 0xff
	info.Subject[0][0].Type[0] = 9
	if value, ok := info.Subject[0][0].Value.([]byte); ok {
		value[0] ^= 0xff
	}
	again, err := request.Info()
	require.NoError(t, err)
	require.Equal(t, []string{"client.example.test"}, again.DNSNames)
	require.Equal(t, "192.0.2.10", again.IPAddresses[0].String())
	require.NotEqual(t, asn1.ObjectIdentifier{9}, again.Subject[0][0].Type)
	for _, set := range again.Subject {
		for _, attribute := range set {
			if value, ok := attribute.Value.(asn1.BitString); ok {
				require.Equal(t, byte(0xaa), value.Bytes[0])
			}
		}
	}
}

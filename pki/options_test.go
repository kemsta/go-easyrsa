package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/v2/crypto"
	"github.com/kemsta/go-easyrsa/v2/pki"
)

func TestBuildClientFull_AppliesRichOptionSet(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true, DNMode: pki.DNModeOrg})
	buildTestCA(t, p)

	notBefore := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	notAfter := notBefore.Add(48 * time.Hour)
	subject := pkix.Name{
		CommonName:   "custom-cn",
		Organization: []string{"Acme Corp"},
		Country:      []string{"US"},
	}

	pair, err := p.BuildClientFull("client1",
		pki.WithKeyAlgo(pki.AlgoECDSA),
		pki.WithCurve(elliptic.P256()),
		pki.WithNotBefore(notBefore),
		pki.WithNotAfter(notAfter),
		pki.WithSubject(subject),
		pki.WithSubjectSerial("SUBJECT-42"),
		pki.WithDNSNames("client.example.com"),
		pki.WithIPAddresses(net.ParseIP("127.0.0.1")),
		pki.WithEmailAddresses("client@example.com"),
		pki.WithCertModifier(func(c *x509.Certificate) {
			c.OCSPServer = []string{"http://ocsp.example.com"}
		}),
	)
	require.NoError(t, err)

	crt, err := pair.Certificate()
	require.NoError(t, err)
	assert.Equal(t, subject.CommonName, crt.Subject.CommonName)
	assert.Equal(t, subject.Organization, crt.Subject.Organization)
	assert.Equal(t, subject.Country, crt.Subject.Country)
	assert.Equal(t, "SUBJECT-42", crt.Subject.SerialNumber)
	assert.WithinDuration(t, notBefore, crt.NotBefore, time.Second)
	assert.WithinDuration(t, notAfter, crt.NotAfter, time.Second)
	assert.Equal(t, []string{"client.example.com"}, crt.DNSNames)
	require.Len(t, crt.IPAddresses, 1)
	assert.Equal(t, "127.0.0.1", crt.IPAddresses[0].String())
	assert.Equal(t, []string{"client@example.com"}, crt.EmailAddresses)
	assert.Equal(t, []string{"http://ocsp.example.com"}, crt.OCSPServer)

	key, err := pair.PrivateKey()
	require.NoError(t, err)
	_, ok := key.(*ecdsa.PrivateKey)
	assert.True(t, ok, "WithKeyAlgo/WithCurve must produce an ECDSA key")
}

func TestSignReq_AppliesCopyCSRExtensionsAndSubjectOverride(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	_, err := p.GenReq("client1",
		pki.WithDNSNames("from-csr.example.com"),
		pki.WithIPAddresses(net.ParseIP("127.0.0.2")),
		pki.WithEmailAddresses("csr@example.com"),
	)
	require.NoError(t, err)

	pair, err := p.SignReq("client1", cert.CertTypeClient,
		pki.WithCopyCSRExtensions(),
		pki.WithSubjectOverride(pkix.Name{
			CommonName:   "override-cn",
			Organization: []string{"Override Org"},
		}),
	)
	require.NoError(t, err)

	crt, err := pair.Certificate()
	require.NoError(t, err)
	assert.Equal(t, "override-cn", crt.Subject.CommonName)
	assert.Equal(t, []string{"Override Org"}, crt.Subject.Organization)
	assert.Equal(t, []string{"from-csr.example.com"}, crt.DNSNames)
	require.Len(t, crt.IPAddresses, 1)
	assert.Equal(t, "127.0.0.2", crt.IPAddresses[0].String())
	assert.Equal(t, []string{"csr@example.com"}, crt.EmailAddresses)
}

func TestSignReq_CertModifierCanChangeSubject(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.GenReq("client1", pki.WithNoPass())
	require.NoError(t, err)

	pair, err := p.SignReq("client1", cert.CertTypeClient,
		pki.WithCertModifier(func(c *x509.Certificate) {
			c.Subject.CommonName = "modified-cn"
		}),
	)
	require.NoError(t, err)
	certificate, err := pair.Certificate()
	require.NoError(t, err)
	assert.Equal(t, "modified-cn", certificate.Subject.CommonName)
}

func TestSignReq_CertModifierCanSetRawSubject(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.GenReq("client1", pki.WithNoPass())
	require.NoError(t, err)
	rawSubject, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "raw-cn"}},
	})
	require.NoError(t, err)

	pair, err := p.SignReq("client1", cert.CertTypeClient,
		pki.WithCertModifier(func(c *x509.Certificate) {
			c.Subject.CommonName = "structured-cn"
			c.RawSubject = rawSubject
		}),
	)
	require.NoError(t, err)
	certificate, err := pair.Certificate()
	require.NoError(t, err)
	assert.Equal(t, "raw-cn", certificate.Subject.CommonName)
}

func TestBuildCA_AppliesSANOptions(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})

	pair, err := p.BuildCA(
		pki.WithDNSNames("ca.example.test"),
		pki.WithIPAddresses(net.ParseIP("127.0.0.1")),
		pki.WithEmailAddresses("ca@example.test"),
	)
	require.NoError(t, err)
	certificate, err := pair.Certificate()
	require.NoError(t, err)
	assert.Equal(t, []string{"ca.example.test"}, certificate.DNSNames)
	require.Len(t, certificate.IPAddresses, 1)
	assert.Equal(t, "127.0.0.1", certificate.IPAddresses[0].String())
	assert.Equal(t, []string{"ca@example.test"}, certificate.EmailAddresses)
}

func TestCertificateOnlySANIsOmittedFromCSRAndAppliedOnSign(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	certificateIP := net.ParseIP("127.0.0.9")
	csrPEM, err := p.GenReq("client1",
		pki.WithNoPass(),
		pki.WithCertificateDNSNames("client.example.test"),
		pki.WithCertificateIPAddresses(certificateIP),
		pki.WithCertificateEmailAddresses("client@example.test"),
	)
	require.NoError(t, err)
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	request, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	assert.Empty(t, request.DNSNames)
	assert.Empty(t, request.IPAddresses)
	assert.Empty(t, request.EmailAddresses)

	pair, err := p.SignReq("client1", cert.CertTypeClient,
		pki.WithCertificateDNSNames("client.example.test"),
		pki.WithCertificateIPAddresses(certificateIP),
		pki.WithCertificateEmailAddresses("client@example.test"),
	)
	require.NoError(t, err)
	certificate, err := pair.Certificate()
	require.NoError(t, err)
	assert.Equal(t, []string{"client.example.test"}, certificate.DNSNames)
	require.Len(t, certificate.IPAddresses, 1)
	assert.Equal(t, "127.0.0.9", certificate.IPAddresses[0].String())
	assert.Equal(t, []string{"client@example.test"}, certificate.EmailAddresses)
}

func TestBuildCA_AppliesSubCAPathLenOption(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})

	pair, err := p.BuildCA(pki.WithSubCAPathLen(0))
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	assert.True(t, crt.MaxPathLenZero)
	assert.Zero(t, crt.MaxPathLen)
}

func TestBuildClientFull_PassphraseAndNoPassOverrides(t *testing.T) {
	t.Run("WithPassphrase encrypts generated key", func(t *testing.T) {
		p := newTestPKI(pki.Config{NoPass: true})
		buildTestCA(t, p)

		pair, err := p.BuildClientFull("encrypted-client",
			pki.WithKeyAlgo(pki.AlgoRSA),
			pki.WithKeySize(1024),
			pki.WithCN("encrypted-cn"),
			pki.WithDays(5),
			pki.WithPassphrase("secret"),
		)
		require.NoError(t, err)

		_, err = pair.PrivateKey()
		assert.Error(t, err, "Pair.PrivateKey expects plaintext PKCS8 and must fail for encrypted keys")
		key, err := pkicrypto.UnmarshalPrivateKey(pair.KeyPEM, "secret")
		require.NoError(t, err)
		require.NotNil(t, key)

		crt, err := pair.Certificate()
		require.NoError(t, err)
		assert.Equal(t, "encrypted-cn", crt.Subject.CommonName)
	})

	t.Run("WithNoPass overrides encrypted default", func(t *testing.T) {
		p := newTestPKI(pki.Config{NoPass: false, CAPassphrase: "ca-pass"})
		buildTestCA(t, p, pki.WithPassphrase("ca-pass"))

		pair, err := p.BuildClientFull("plain-client", pki.WithNoPass())
		require.NoError(t, err)
		_, err = pair.PrivateKey()
		require.NoError(t, err)
	})
}

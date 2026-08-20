package pki_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func TestShowEKUUsesRegularPathBeforeEntityLookup(t *testing.T) {
	t.Parallel()

	pk := newTestPKI(pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	buildTestCA(t, pk)
	_, err := pk.BuildClientFull("client")
	require.NoError(t, err)
	server, err := pk.BuildServerFull("server")
	require.NoError(t, err)
	certificatePath := filepath.Join(t.TempDir(), "server.crt")
	require.NoError(t, os.WriteFile(certificatePath, server.CertPEM, 0o600))

	classification, err := pk.ShowEKU(certificatePath)
	require.NoError(t, err)
	require.Equal(t, cert.EKUServer, classification)
	classification, err = pk.ShowEKU("client")
	require.NoError(t, err)
	require.Equal(t, cert.EKUClient, classification)

	malformed := filepath.Join(t.TempDir(), "malformed.crt")
	require.NoError(t, os.WriteFile(malformed, []byte("not a certificate"), 0o600))
	_, err = pk.ShowEKU(malformed)
	require.Error(t, err)

	if runtime.GOOS != "windows" {
		symlink := filepath.Join(t.TempDir(), "server-link.crt")
		require.NoError(t, os.Symlink(certificatePath, symlink))
		classification, err = pk.ShowEKU(symlink)
		require.NoError(t, err)
		require.Equal(t, cert.EKUServer, classification)
	}
}

func TestDisplayDNPreservesRawRDNStructure(t *testing.T) {
	t.Parallel()

	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	commonNameOID := asn1.ObjectIdentifier{2, 5, 4, 3}
	unitOID := asn1.ObjectIdentifier{2, 5, 4, 11}
	rawSequence := pkix.RDNSequence{
		{{Type: commonNameOID, Value: "display-name"}, {Type: unknownOID, Value: "unknown-value"}},
		{{Type: unitOID, Value: "first"}},
		{{Type: unitOID, Value: "second"}},
	}
	rawSubject, err := asn1.Marshal(rawSequence)
	require.NoError(t, err)

	pk := newTestPKI(pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	buildTestCA(t, pk)
	pair, err := pk.BuildClientFull("display", pki.WithCertModifier(func(template *x509.Certificate) {
		template.RawSubject = append([]byte(nil), rawSubject...)
	}))
	require.NoError(t, err)
	certificatePath := filepath.Join(t.TempDir(), "display.crt")
	require.NoError(t, os.WriteFile(certificatePath, pair.CertPEM, 0o600))

	requestKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{RawSubject: rawSubject}, requestKey)
	require.NoError(t, err)
	requestPath := filepath.Join(t.TempDir(), "display.req")
	require.NoError(t, os.WriteFile(requestPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER}), 0o600))

	for _, test := range []struct {
		form pki.DNForm
		path string
	}{
		{form: pki.DNFormX509, path: certificatePath},
		{form: pki.DNFormRequest, path: requestPath},
	} {
		sequence, err := pk.DisplayDN(test.form, test.path)
		require.NoError(t, err)
		require.Len(t, sequence, 3)
		require.Len(t, sequence[0], 2)
		require.True(t, sequence[0][0].Type.Equal(commonNameOID) || sequence[0][1].Type.Equal(commonNameOID))
		sequence[0][0].Type[0] = 9
		again, err := pk.DisplayDN(test.form, test.path)
		require.NoError(t, err)
		require.NotEqual(t, 9, again[0][0].Type[0])
	}

	_, err = pk.DisplayDN(pki.DNForm("invalid"), certificatePath)
	require.Error(t, err)
	_, err = pk.DisplayDN(pki.DNFormX509, t.TempDir())
	require.Error(t, err)
}

func TestRandStreamsLowercaseHexAndPropagatesDestinationFailure(t *testing.T) {
	t.Parallel()

	pk, err := pki.NewWithMemory(pki.Config{})
	require.NoError(t, err)
	var output bytes.Buffer
	require.NoError(t, pk.Rand(32, &output))
	require.Len(t, output.Bytes(), 65)
	require.Equal(t, byte('\n'), output.Bytes()[64])
	decoded, err := hex.DecodeString(string(output.Bytes()[:64]))
	require.NoError(t, err)
	require.Len(t, decoded, 32)

	require.Error(t, pk.Rand(0, io.Discard))
	require.Error(t, pk.Rand(-1, io.Discard))
	require.Error(t, pk.Rand(1, nil))
	writeErr := errors.New("destination failed")
	require.ErrorIs(t, pk.Rand(32, failingUtilityWriter{err: writeErr}), writeErr)
	require.ErrorIs(t, pk.Rand(1, newlineShortWriter{}), io.ErrShortWrite)
}

type failingUtilityWriter struct{ err error }

func (w failingUtilityWriter) Write([]byte) (int, error) { return 0, w.err }

type newlineShortWriter struct{}

func (newlineShortWriter) Write(data []byte) (int, error) {
	if bytes.Equal(data, []byte("\n")) {
		return 0, nil
	}
	return len(data), nil
}

func TestSerialDelegatesToDeepCopyingCheckSerial(t *testing.T) {
	t.Parallel()

	pk := newTestPKI(pki.Config{NoPass: true, SequentialSerial: true})
	pair, err := pk.BuildCA()
	require.NoError(t, err)
	serial, err := pair.Serial()
	require.NoError(t, err)
	entry, err := pk.Serial(serial)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, storage.StatusValid, entry.Status)
	entry.Serial.SetInt64(999)
	again, err := pk.Serial(serial)
	require.NoError(t, err)
	require.Zero(t, again.Serial.Cmp(serial))
}

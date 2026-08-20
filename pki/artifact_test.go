package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"

	pkicrypto "github.com/kemsta/go-easyrsa/v2/crypto"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
)

func newMemoryArtifactPKI(t *testing.T, cfg pki.Config) (*memory.Backend, *pki.PKI) {
	t.Helper()
	backend := memory.NewBackend()
	pk, err := pki.New(cfg, backend)
	require.NoError(t, err)
	return backend, pk
}

func requireMemoryArtifact(t *testing.T, backend storage.Backend, name string, want []byte, visibility storage.ArtifactVisibility) {
	t.Helper()
	require.NoError(t, backend.View(func(components storage.Components) error {
		artifact, err := components.Artifacts().GetArtifact(name)
		require.NoError(t, err)
		require.Equal(t, want, artifact.Data)
		require.Equal(t, visibility, artifact.Visibility)
		return nil
	}))
}

func TestExportArtifactsPersistExactBytesAndVariants(t *testing.T) {
	t.Parallel()

	backend, pk := newMemoryArtifactPKI(t, pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	_, err := pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("client")
	require.NoError(t, err)

	p12, err := pk.ExportP12("client", pki.ExportP12Options{Password: "bundle"})
	require.NoError(t, err)
	requireMemoryArtifact(t, backend, "private/client.p12", p12, storage.ArtifactPrivate)
	privateKey, certificate, caCertificates, err := gopkcs12.DecodeChain(p12, "bundle")
	require.NoError(t, err)
	require.NotNil(t, privateKey)
	require.Equal(t, "client", certificate.Subject.CommonName)
	require.Len(t, caCertificates, 1)

	p12NoCA, err := pk.ExportP12("client", pki.ExportP12Options{Password: "bundle", NoCA: true})
	require.NoError(t, err)
	_, _, caCertificates, err = gopkcs12.DecodeChain(p12NoCA, "bundle")
	require.NoError(t, err)
	require.Empty(t, caCertificates)

	p12NoKey, err := pk.ExportP12("client", pki.ExportP12Options{Password: "bundle", NoKey: true})
	require.NoError(t, err)
	trustCertificates, err := gopkcs12.DecodeTrustStore(p12NoKey, "bundle")
	require.NoError(t, err)
	require.Len(t, trustCertificates, 2)

	p12Passwordless, err := pk.ExportP12("client", pki.ExportP12Options{})
	require.NoError(t, err)
	_, _, _, err = gopkcs12.DecodeChain(p12Passwordless, "")
	require.NoError(t, err)

	p12Legacy, err := pk.ExportP12("client", pki.ExportP12Options{Password: "bundle", Legacy: true})
	require.NoError(t, err)
	_, _, _, err = gopkcs12.DecodeChain(p12Legacy, "bundle")
	require.NoError(t, err)

	p7, err := pk.ExportP7("client", pki.ExportP7Options{NoCA: true})
	require.NoError(t, err)
	requireMemoryArtifact(t, backend, "issued/client.p7b", p7, storage.ArtifactPublic)
	p7Block, _ := pem.Decode(p7)
	require.NotNil(t, p7Block)
	parsedP7, err := pkcs7.Parse(p7Block.Bytes)
	require.NoError(t, err)
	require.Len(t, parsedP7.Certificates, 1)
	p7WithCA, err := pk.ExportP7("client", pki.ExportP7Options{})
	require.NoError(t, err)
	p7Block, _ = pem.Decode(p7WithCA)
	require.NotNil(t, p7Block)
	parsedP7, err = pkcs7.Parse(p7Block.Bytes)
	require.NoError(t, err)
	require.Len(t, parsedP7.Certificates, 2)

	p8, err := pk.ExportP8("client", "output-pass")
	require.NoError(t, err)
	requireMemoryArtifact(t, backend, "private/client.p8", p8, storage.ArtifactPrivate)
	_, err = pkicrypto.UnmarshalPrivateKey(p8, "output-pass")
	require.NoError(t, err)

	p1, err := pk.ExportP1("client", "output-pass")
	require.NoError(t, err)
	requireMemoryArtifact(t, backend, "private/client.p1", p1, storage.ArtifactPrivate)
	p1Block, _ := pem.Decode(p1)
	require.NotNil(t, p1Block)
	decrypted, err := x509.DecryptPEMBlock(p1Block, []byte("output-pass")) //nolint:staticcheck // validates Easy-RSA-compatible legacy PEM encryption.
	require.NoError(t, err)
	_, err = x509.ParsePKCS1PrivateKey(decrypted)
	require.NoError(t, err)
}

func TestP8AndP1ExportPendingKeyWithoutCertificate(t *testing.T) {
	t.Parallel()

	backend, pk := newMemoryArtifactPKI(t, pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	_, err := pk.GenReq("pending")
	require.NoError(t, err)
	p8, err := pk.ExportP8("pending", "")
	require.NoError(t, err)
	requireMemoryArtifact(t, backend, "private/pending.p8", p8, storage.ArtifactPrivate)
	_, err = pkicrypto.UnmarshalPrivateKey(p8, "")
	require.NoError(t, err)
	p1, err := pk.ExportP1("pending", "")
	require.NoError(t, err)
	requireMemoryArtifact(t, backend, "private/pending.p1", p1, storage.ArtifactPrivate)
	p1Block, _ := pem.Decode(p1)
	require.NotNil(t, p1Block)
	_, err = x509.ParsePKCS1PrivateKey(p1Block.Bytes)
	require.NoError(t, err)
}

func TestCAKeyExportsUseCAPassphrase(t *testing.T) {
	t.Parallel()

	backend, pk := newMemoryArtifactPKI(t, pki.Config{
		CAPassphrase:  "ca-secret",
		KeyPassphrase: "wrong-non-ca-passphrase",
		KeyAlgo:       pki.AlgoRSA,
		KeySize:       1024,
	})
	_, err := pk.BuildCA(pki.WithPassphrase("ca-secret"))
	require.NoError(t, err)
	p8, err := pk.ExportP8("ca", "output")
	require.NoError(t, err)
	requireMemoryArtifact(t, backend, "private/ca.p8", p8, storage.ArtifactPrivate)
	p1, err := pk.ExportP1("ca", "output")
	require.NoError(t, err)
	requireMemoryArtifact(t, backend, "private/ca.p1", p1, storage.ArtifactPrivate)
	p12, err := pk.ExportP12("ca", pki.ExportP12Options{Password: "output", NoCA: true})
	require.NoError(t, err)
	requireMemoryArtifact(t, backend, "private/ca.p12", p12, storage.ArtifactPrivate)
}

func TestExportArtifactsPersistFilesystemPathsAndModes(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("client")
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
		mode os.FileMode
		run  func() ([]byte, error)
	}{
		{name: "p12", path: filepath.Join("private", "client.p12"), mode: 0o600, run: func() ([]byte, error) {
			return pk.ExportP12("client", pki.ExportP12Options{Password: "bundle"})
		}},
		{name: "p7", path: filepath.Join("issued", "client.p7b"), mode: 0o644, run: func() ([]byte, error) {
			return pk.ExportP7("client", pki.ExportP7Options{})
		}},
		{name: "p8", path: filepath.Join("private", "client.p8"), mode: 0o600, run: func() ([]byte, error) {
			return pk.ExportP8("client", "output")
		}},
		{name: "p1", path: filepath.Join("private", "client.p1"), mode: 0o600, run: func() ([]byte, error) {
			return pk.ExportP1("client", "output")
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			data, err := test.run()
			require.NoError(t, err)
			fullPath := filepath.Join(pkiDir, test.path)
			require.Equal(t, data, readArtifactFile(t, fullPath))
			if runtime.GOOS != "windows" {
				info, err := os.Stat(fullPath)
				require.NoError(t, err)
				require.Equal(t, test.mode, info.Mode().Perm())
			}
		})
	}
}

func TestGeneratedCRLAndDHPersistFilesystemArtifacts(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)

	crlPEM, err := pk.GenCRL()
	require.NoError(t, err)
	require.Equal(t, crlPEM, readArtifactFile(t, filepath.Join(pkiDir, "crl.pem")))
	crlBlock, _ := pem.Decode(crlPEM)
	require.NotNil(t, crlBlock)
	crlDER := readArtifactFile(t, filepath.Join(pkiDir, "crl.der"))
	require.Equal(t, crlBlock.Bytes, crlDER)
	_, err = x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	dh, err := pk.GenDH(128)
	require.NoError(t, err)
	require.Equal(t, dh, readArtifactFile(t, filepath.Join(pkiDir, "dh.pem")))

	if runtime.GOOS != "windows" {
		for _, name := range []string{"crl.pem", "crl.der", "dh.pem"} {
			info, err := os.Stat(filepath.Join(pkiDir, name))
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
		}
	}
}

type artifactFailureBackend struct {
	storage.Backend
	err error
}

func (b *artifactFailureBackend) Update(fn func(storage.Components) error) error {
	return b.Backend.Update(func(components storage.Components) error {
		return fn(artifactFailureComponents{Components: components, err: b.err})
	})
}

type artifactFailureComponents struct {
	storage.Components
	err error
}

func (c artifactFailureComponents) Artifacts() storage.ArtifactStorage {
	return artifactFailureStorage{ArtifactStorage: c.Components.Artifacts(), err: c.err}
}

type artifactFailureStorage struct {
	storage.ArtifactStorage
	err error
}

func (s artifactFailureStorage) PutArtifact(storage.Artifact) error { return s.err }

func TestArtifactFailurePreservesExistingCRLTransactionally(t *testing.T) {
	t.Parallel()

	backend := memory.NewBackend()
	cleanPKI, err := pki.New(pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024}, backend)
	require.NoError(t, err)
	_, err = cleanPKI.BuildCA()
	require.NoError(t, err)
	originalPEM, err := cleanPKI.GenCRL()
	require.NoError(t, err)
	originalBlock, _ := pem.Decode(originalPEM)
	require.NotNil(t, originalBlock)

	writeErr := errors.New("artifact write failed")
	failingPKI, err := pki.New(pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024}, &artifactFailureBackend{Backend: backend, err: writeErr})
	require.NoError(t, err)
	_, err = failingPKI.GenCRL()
	require.ErrorIs(t, err, writeErr)

	crl, err := cleanPKI.ShowCRL()
	require.NoError(t, err)
	require.Equal(t, originalBlock.Bytes, crl.Raw)
	requireMemoryArtifact(t, backend, "crl.pem", originalPEM, storage.ArtifactPublic)
	requireMemoryArtifact(t, backend, "crl.der", originalBlock.Bytes, storage.ArtifactPublic)
}

func TestGenCRLReplacesArtifactsAndResetRemovesBoth(t *testing.T) {
	t.Parallel()

	backend, pk := newMemoryArtifactPKI(t, pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	_, err := pk.BuildCA()
	require.NoError(t, err)
	firstPEM, err := pk.GenCRL()
	require.NoError(t, err)
	secondPEM, err := pk.GenCRL()
	require.NoError(t, err)
	require.NotEqual(t, firstPEM, secondPEM)
	secondBlock, _ := pem.Decode(secondPEM)
	require.NotNil(t, secondBlock)
	requireMemoryArtifact(t, backend, "crl.pem", secondPEM, storage.ArtifactPublic)
	requireMemoryArtifact(t, backend, "crl.der", secondBlock.Bytes, storage.ArtifactPublic)

	require.NoError(t, pk.ResetCRL())
	crl, err := pk.ShowCRL()
	require.NoError(t, err)
	require.Empty(t, crl.Raw)
	require.NoError(t, backend.View(func(components storage.Components) error {
		_, err := components.Artifacts().GetArtifact("crl.pem")
		require.ErrorIs(t, err, storage.ErrNotFound)
		_, err = components.Artifacts().GetArtifact("crl.der")
		require.ErrorIs(t, err, storage.ErrNotFound)
		return nil
	}))
}

func readArtifactFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	require.NoError(t, err)
	return data
}

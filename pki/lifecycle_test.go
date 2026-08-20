package pki_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	fsstore "github.com/kemsta/go-easyrsa/v2/storage/fs"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
)

type lifecycleBackendCase struct {
	name   string
	create func(t *testing.T) (storage.Backend, string)
}

func lifecycleBackends() []lifecycleBackendCase {
	return []lifecycleBackendCase{
		{name: "memory", create: func(t *testing.T) (storage.Backend, string) {
			return memory.NewBackend(), ""
		}},
		{name: "filesystem", create: func(t *testing.T) (storage.Backend, string) {
			directory := filepath.Join(t.TempDir(), "pki")
			return fsstore.NewBackend(directory, "ca"), directory
		}},
	}
}

func newLifecyclePKI(t *testing.T, backend storage.Backend) *pki.PKI {
	t.Helper()
	require.NoError(t, backend.EnsureLayout())
	pk, err := pki.New(pki.Config{
		NoPass:           true,
		SequentialSerial: true,
		KeyAlgo:          pki.AlgoRSA,
		KeySize:          1024,
	}, backend)
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	return pk
}

func putDerivedArtifacts(t *testing.T, backend storage.Backend, name string) {
	t.Helper()
	require.NoError(t, backend.Update(func(components storage.Components) error {
		for _, artifact := range []storage.Artifact{
			{Path: filepath.ToSlash(filepath.Join("private", name+".p12")), Data: []byte("p12"), Visibility: storage.ArtifactPrivate},
			{Path: filepath.ToSlash(filepath.Join("private", name+".p8")), Data: []byte("p8"), Visibility: storage.ArtifactPrivate},
			{Path: filepath.ToSlash(filepath.Join("private", name+".p1")), Data: []byte("p1"), Visibility: storage.ArtifactPrivate},
			{Path: filepath.ToSlash(filepath.Join("issued", name+".p7b")), Data: []byte("p7"), Visibility: storage.ArtifactPublic},
			{Path: filepath.ToSlash(filepath.Join("inline", name+".inline")), Data: []byte("inline"), Visibility: storage.ArtifactPublic},
			{Path: filepath.ToSlash(filepath.Join("inline", "private", name+".inline")), Data: []byte("inline-private"), Visibility: storage.ArtifactPrivate},
		} {
			if err := components.Artifacts().PutArtifact(artifact); err != nil {
				return err
			}
		}
		return nil
	}))
}

func requireDerivedArtifactsAbsent(t *testing.T, backend storage.Backend, name string) {
	t.Helper()
	require.NoError(t, backend.View(func(components storage.Components) error {
		for _, artifactPath := range []string{
			filepath.ToSlash(filepath.Join("private", name+".p12")),
			filepath.ToSlash(filepath.Join("private", name+".p8")),
			filepath.ToSlash(filepath.Join("private", name+".p1")),
			filepath.ToSlash(filepath.Join("issued", name+".p7b")),
			filepath.ToSlash(filepath.Join("inline", name+".inline")),
			filepath.ToSlash(filepath.Join("inline", "private", name+".inline")),
		} {
			_, err := components.Artifacts().GetArtifact(artifactPath)
			require.ErrorIs(t, err, storage.ErrNotFound, artifactPath)
		}
		return nil
	}))
}

func TestExpireAndRevokeExpiredAcrossWritableBackends(t *testing.T) {
	for _, backendCase := range lifecycleBackends() {
		backendCase := backendCase
		t.Run(backendCase.name, func(t *testing.T) {
			t.Parallel()
			backend, pkiDir := backendCase.create(t)
			pk := newLifecyclePKI(t, backend)
			pair, err := pk.BuildClientFull("expired")
			require.NoError(t, err)
			serial, err := pair.Serial()
			require.NoError(t, err)
			putDerivedArtifacts(t, backend, "expired")

			require.NoError(t, pk.Expire("expired"))
			entry, err := pk.CheckSerial(serial)
			require.NoError(t, err)
			require.Equal(t, storage.StatusValid, entry.Status)
			_, err = pk.ShowCert("expired")
			require.ErrorIs(t, err, storage.ErrNotFound)
			require.NoError(t, backend.View(func(components storage.Components) error {
				expired, err := components.Lifecycle().GetExpiredCertificate("expired")
				require.NoError(t, err)
				require.Equal(t, pair.CertPEM, expired)
				_, err = components.Keys().GetPrivateKey("expired")
				require.NoError(t, err)
				_, err = components.CSRs().GetCSR("expired")
				return err
			}))
			if pkiDir != "" {
				require.FileExists(t, filepath.Join(pkiDir, "expired", "expired.crt"))
				require.NoFileExists(t, filepath.Join(pkiDir, "issued", "expired.crt"))
			}

			require.NoError(t, pk.RevokeExpired("expired", cert.ReasonCessationOfOperation))
			requireDerivedArtifactsAbsent(t, backend, "expired")
			entry, err = pk.CheckSerial(serial)
			require.NoError(t, err)
			require.Equal(t, storage.StatusRevoked, entry.Status)
			revokedByCRL, err := pk.IsRevoked(serial)
			require.NoError(t, err)
			require.False(t, revokedByCRL)
			require.NoError(t, backend.View(func(components storage.Components) error {
				_, err := components.Lifecycle().GetExpiredCertificate("expired")
				require.ErrorIs(t, err, storage.ErrNotFound)
				_, err = components.Keys().GetPrivateKey("expired")
				require.NoError(t, err)
				_, err = components.CSRs().GetCSR("expired")
				return err
			}))
			if pkiDir != "" {
				require.FileExists(t, filepath.Join(pkiDir, "revoked", "certs_by_serial", storage.HexSerial(serial)+".crt"))
				require.FileExists(t, filepath.Join(pkiDir, "private", "expired.key"))
				require.FileExists(t, filepath.Join(pkiDir, "reqs", "expired.req"))
			}
		})
	}
}

func TestExpireRejectsOccupiedDestinationWithoutMovingReplacement(t *testing.T) {
	t.Parallel()

	backend := memory.NewBackend()
	pk := newLifecyclePKI(t, backend)
	_, err := pk.BuildClientFull("client")
	require.NoError(t, err)
	require.NoError(t, pk.Expire("client"))
	replacement, err := pk.BuildClientFull("client")
	require.NoError(t, err)
	replacementSerial, err := replacement.Serial()
	require.NoError(t, err)

	err = pk.Expire("client")
	require.ErrorIs(t, err, storage.ErrConflict)
	current, err := pk.ShowCert("client")
	require.NoError(t, err)
	currentSerial, err := current.Serial()
	require.NoError(t, err)
	require.Zero(t, currentSerial.Cmp(replacementSerial))
}

func TestRevokeExpiredPreservesReplacementButRemovesNameArtifacts(t *testing.T) {
	t.Parallel()

	backend := memory.NewBackend()
	pk := newLifecyclePKI(t, backend)
	oldPair, err := pk.BuildClientFull("client")
	require.NoError(t, err)
	oldSerial, err := oldPair.Serial()
	require.NoError(t, err)
	require.NoError(t, pk.Expire("client"))
	replacement, err := pk.BuildClientFull("client")
	require.NoError(t, err)
	replacementSerial, err := replacement.Serial()
	require.NoError(t, err)
	putDerivedArtifacts(t, backend, "client")

	require.NoError(t, pk.RevokeExpired("client", cert.ReasonUnspecified))
	requireDerivedArtifactsAbsent(t, backend, "client")
	current, err := pk.ShowCert("client")
	require.NoError(t, err)
	currentSerial, err := current.Serial()
	require.NoError(t, err)
	require.Zero(t, currentSerial.Cmp(replacementSerial))
	oldEntry, err := pk.CheckSerial(oldSerial)
	require.NoError(t, err)
	require.Equal(t, storage.StatusRevoked, oldEntry.Status)
}

func TestRevokeIssuedAcrossWritableBackends(t *testing.T) {
	for _, backendCase := range lifecycleBackends() {
		backendCase := backendCase
		t.Run(backendCase.name, func(t *testing.T) {
			t.Parallel()
			backend, pkiDir := backendCase.create(t)
			pk := newLifecyclePKI(t, backend)
			pair, err := pk.BuildClientFull("issued")
			require.NoError(t, err)
			serial, err := pair.Serial()
			require.NoError(t, err)
			putDerivedArtifacts(t, backend, "issued")
			var sourceModes map[string]os.FileMode
			if pkiDir != "" {
				sourceModes = make(map[string]os.FileMode)
				for kind, source := range map[string]string{
					"cert": filepath.Join(pkiDir, "issued", "issued.crt"),
					"key":  filepath.Join(pkiDir, "private", "issued.key"),
					"req":  filepath.Join(pkiDir, "reqs", "issued.req"),
				} {
					info, err := os.Stat(source)
					require.NoError(t, err)
					sourceModes[kind] = info.Mode().Perm()
				}
			}

			require.NoError(t, pk.RevokeIssued("issued", cert.ReasonKeyCompromise))
			entry, err := pk.CheckSerial(serial)
			require.NoError(t, err)
			require.Equal(t, storage.StatusRevoked, entry.Status)
			requireDerivedArtifactsAbsent(t, backend, "issued")
			require.NoError(t, backend.View(func(components storage.Components) error {
				_, err := components.Keys().GetPrivateKey("issued")
				require.ErrorIs(t, err, storage.ErrNotFound)
				_, err = components.CSRs().GetCSR("issued")
				require.ErrorIs(t, err, storage.ErrNotFound)
				return nil
			}))
			revokedByCRL, err := pk.IsRevoked(serial)
			require.NoError(t, err)
			require.False(t, revokedByCRL)
			_, err = pk.GenCRL()
			require.NoError(t, err)
			revokedByCRL, err = pk.IsRevoked(serial)
			require.NoError(t, err)
			require.True(t, revokedByCRL)
			if pkiDir != "" {
				hexSerial := storage.HexSerial(serial)
				archived := map[string]string{
					"cert": filepath.Join(pkiDir, "revoked", "certs_by_serial", hexSerial+".crt"),
					"key":  filepath.Join(pkiDir, "revoked", "private_by_serial", hexSerial+".key"),
					"req":  filepath.Join(pkiDir, "revoked", "reqs_by_serial", hexSerial+".req"),
				}
				for kind, name := range archived {
					info, err := os.Stat(name)
					require.NoError(t, err)
					require.Equal(t, sourceModes[kind], info.Mode().Perm())
				}
			}
		})
	}
}

func TestRenewArchivesCertificateAndRemovesDerivedArtifacts(t *testing.T) {
	for _, backendCase := range lifecycleBackends() {
		backendCase := backendCase
		t.Run(backendCase.name, func(t *testing.T) {
			t.Parallel()
			backend, pkiDir := backendCase.create(t)
			pk := newLifecyclePKI(t, backend)
			oldPair, err := pk.BuildClientFull("renewed", pki.WithDNSNames("renewed.example.test"))
			require.NoError(t, err)
			oldCertificate, err := oldPair.Certificate()
			require.NoError(t, err)
			oldSerial := new(big.Int).Set(oldCertificate.SerialNumber)
			putDerivedArtifacts(t, backend, "renewed")

			newPair, err := pk.Renew("renewed")
			require.NoError(t, err)
			newCertificate, err := newPair.Certificate()
			require.NoError(t, err)
			require.Equal(t, oldCertificate.DNSNames, newCertificate.DNSNames)
			require.NotZero(t, oldSerial.Cmp(newCertificate.SerialNumber))
			requireDerivedArtifactsAbsent(t, backend, "renewed")
			require.NoError(t, backend.View(func(components storage.Components) error {
				archived, err := components.Lifecycle().GetRenewedCertificate("renewed")
				require.NoError(t, err)
				require.Equal(t, oldPair.CertPEM, archived)
				oldBySerial, err := components.Keys().GetBySerial(oldSerial)
				require.NoError(t, err)
				require.Equal(t, oldPair.CertPEM, oldBySerial.CertPEM)
				_, err = components.Keys().GetPrivateKey("renewed")
				require.NoError(t, err)
				_, err = components.CSRs().GetCSR("renewed")
				return err
			}))
			oldEntry, err := pk.CheckSerial(oldSerial)
			require.NoError(t, err)
			require.Equal(t, storage.StatusExpired, oldEntry.Status)
			newEntry, err := pk.CheckSerial(newCertificate.SerialNumber)
			require.NoError(t, err)
			require.Equal(t, storage.StatusValid, newEntry.Status)
			_, err = pk.Renew("renewed")
			require.ErrorIs(t, err, storage.ErrConflict)
			if pkiDir != "" {
				require.FileExists(t, filepath.Join(pkiDir, "renewed", "issued", "renewed.crt"))
				require.FileExists(t, filepath.Join(pkiDir, "issued", "renewed.crt"))
			}
		})
	}
}

type artifactDeleteFailureBackend struct {
	storage.Backend
	err error
}

func (b *artifactDeleteFailureBackend) Update(fn func(storage.Components) error) error {
	return b.Backend.Update(func(components storage.Components) error {
		return fn(artifactDeleteFailureComponents{Components: components, err: b.err})
	})
}

type artifactDeleteFailureComponents struct {
	storage.Components
	err error
}

func (c artifactDeleteFailureComponents) Artifacts() storage.ArtifactStorage {
	return artifactDeleteFailureStorage{ArtifactStorage: c.Components.Artifacts(), err: c.err}
}

type artifactDeleteFailureStorage struct {
	storage.ArtifactStorage
	err error
}

func (s artifactDeleteFailureStorage) DeleteArtifact(string) error { return s.err }

func TestFilesystemLifecycleDestinationConflictPreservesSource(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	pair, err := pk.BuildClientFull("client")
	require.NoError(t, err)
	serial, err := pair.Serial()
	require.NoError(t, err)
	destination := filepath.Join(pkiDir, "revoked", "certs_by_serial", storage.HexSerial(serial)+".crt")
	require.NoError(t, os.MkdirAll(destination, 0o755))

	err = pk.RevokeIssued("client", cert.ReasonUnspecified)
	require.ErrorIs(t, err, storage.ErrConflict)
	require.FileExists(t, filepath.Join(pkiDir, "issued", "client.crt"))
	require.DirExists(t, destination)
}

func TestFilesystemIndexFailureRollsBackLifecycleMoves(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	backend := fsstore.NewBackend(pkiDir, "ca")
	goodPKI := newLifecyclePKI(t, backend)
	_, err := goodPKI.BuildClientFull("revoke-failure")
	require.NoError(t, err)
	_, err = goodPKI.BuildClientFull("renew-failure")
	require.NoError(t, err)
	updateErr := errors.New("index update failed")
	failingPKI, err := pki.New(pki.Config{NoPass: true}, &indexUpdateFailureBackend{Backend: backend, err: updateErr})
	require.NoError(t, err)

	require.ErrorIs(t, failingPKI.RevokeIssued("revoke-failure", cert.ReasonUnspecified), updateErr)
	require.FileExists(t, filepath.Join(pkiDir, "issued", "revoke-failure.crt"))
	require.NoDirExists(t, filepath.Join(pkiDir, "revoked"))
	_, err = failingPKI.Renew("renew-failure")
	require.ErrorIs(t, err, updateErr)
	require.FileExists(t, filepath.Join(pkiDir, "issued", "renew-failure.crt"))
	require.NoFileExists(t, filepath.Join(pkiDir, "renewed", "issued", "renew-failure.crt"))
}

func TestLifecycleArtifactCleanupFailureRollsBackArchive(t *testing.T) {
	t.Parallel()

	backend := memory.NewBackend()
	goodPKI := newLifecyclePKI(t, backend)
	pair, err := goodPKI.BuildClientFull("client")
	require.NoError(t, err)
	serial, err := pair.Serial()
	require.NoError(t, err)
	putDerivedArtifacts(t, backend, "client")
	deleteErr := errors.New("artifact delete failed")
	failingPKI, err := pki.New(pki.Config{NoPass: true}, &artifactDeleteFailureBackend{Backend: backend, err: deleteErr})
	require.NoError(t, err)

	err = failingPKI.RevokeIssued("client", cert.ReasonUnspecified)
	require.ErrorIs(t, err, deleteErr)
	current, err := goodPKI.ShowCert("client")
	require.NoError(t, err)
	currentSerial, err := current.Serial()
	require.NoError(t, err)
	require.Zero(t, currentSerial.Cmp(serial))
	entry, err := goodPKI.CheckSerial(serial)
	require.NoError(t, err)
	require.Equal(t, storage.StatusValid, entry.Status)
	require.NoError(t, backend.View(func(components storage.Components) error {
		_, err := components.Artifacts().GetArtifact("private/client.p12")
		return err
	}))
}

func TestRenewPreservesSignatureDigestAndCriticalSAN(t *testing.T) {
	t.Parallel()

	pk := newTestPKI(pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	buildTestCA(t, pk)
	sanDER, err := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte("critical.example.test")}})
	require.NoError(t, err)
	customValue, err := asn1.Marshal("custom-profile")
	require.NoError(t, err)
	customOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}
	oldPair, err := pk.BuildClientFull("critical", pki.WithCertModifier(func(template *x509.Certificate) {
		template.SignatureAlgorithm = x509.SHA512WithRSA
		template.ExtraExtensions = append(template.ExtraExtensions,
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: sanDER},
			pkix.Extension{Id: customOID, Critical: true, Value: customValue},
		)
	}))
	require.NoError(t, err)
	oldCertificate, err := oldPair.Certificate()
	require.NoError(t, err)
	require.Equal(t, x509.SHA512WithRSA, oldCertificate.SignatureAlgorithm)
	require.True(t, extensionCritical(oldCertificate, asn1.ObjectIdentifier{2, 5, 29, 17}))
	require.True(t, extensionCritical(oldCertificate, customOID))

	overriddenSubjectKeyID := []byte{9, 8, 7, 6}
	newPair, err := pk.Renew("critical", pki.WithCertModifier(func(template *x509.Certificate) {
		template.SubjectKeyId = append([]byte(nil), overriddenSubjectKeyID...)
	}))
	require.NoError(t, err)
	newCertificate, err := newPair.Certificate()
	require.NoError(t, err)
	require.Equal(t, oldCertificate.SignatureAlgorithm, newCertificate.SignatureAlgorithm)
	require.Equal(t, overriddenSubjectKeyID, newCertificate.SubjectKeyId)
	require.Equal(t, oldCertificate.DNSNames, newCertificate.DNSNames)
	require.True(t, extensionCritical(newCertificate, asn1.ObjectIdentifier{2, 5, 29, 17}))
	require.True(t, extensionCritical(newCertificate, customOID))
	require.Equal(t, extensionValue(oldCertificate, customOID), extensionValue(newCertificate, customOID))
}

func extensionValue(certificate *x509.Certificate, oid asn1.ObjectIdentifier) []byte {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oid) {
			return extension.Value
		}
	}
	return nil
}

func extensionCritical(certificate *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oid) {
			return extension.Critical
		}
	}
	return false
}

func TestLifecycleRejectsSelfSignedCA(t *testing.T) {
	t.Parallel()

	pk := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, pk)
	require.Error(t, pk.Expire("ca"))
	require.Error(t, pk.RevokeIssued("ca", cert.ReasonUnspecified))
	require.Error(t, func() error {
		_, err := pk.Renew("ca")
		return err
	}())
}

func TestRevokeIssuedUsesStorageNameWhenCNDiffers(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.NewWithFS(pkiDir, pki.Config{
		NoPass:       true,
		KeyAlgo:      pki.AlgoRSA,
		KeySize:      1024,
		DNMode:       pki.DNModeOrg,
		SubjTemplate: pkix.Name{Organization: []string{"Acme"}},
	})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.GenReq("storage-name")
	require.NoError(t, err)
	pair, err := pk.SignReq("storage-name", cert.CertTypeClient, pki.WithSubjectOverride(pkix.Name{CommonName: "different-cn", Organization: []string{"Acme"}}))
	require.NoError(t, err)
	serial, err := pair.Serial()
	require.NoError(t, err)
	// Simulate an Easy-RSA-produced certificate, which has no Go .name sidecar.
	require.NoError(t, os.Remove(filepath.Join(pkiDir, "certs_by_serial", storage.HexSerial(serial)+".name")))
	require.NoError(t, pk.RevokeIssued("storage-name", cert.ReasonUnspecified))
	require.FileExists(t, filepath.Join(pkiDir, "revoked", "certs_by_serial", storage.HexSerial(serial)+".crt"))
	revoked, err := pk.ShowCert("storage-name")
	require.NoError(t, err)
	require.Equal(t, "storage-name", revoked.Name)
}

func TestFilesystemHistoricalPairsNeverUseUnrelatedCurrentKey(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	backend := fsstore.NewBackend(pkiDir, "ca")
	pk := newLifecyclePKI(t, backend)
	oldRevoked, err := pk.BuildClientFull("revoked-name")
	require.NoError(t, err)
	oldRevokedSerial, err := oldRevoked.Serial()
	require.NoError(t, err)
	require.NoError(t, pk.RevokeIssued("revoked-name", cert.ReasonUnspecified))
	newRevoked, err := pk.BuildClientFull("revoked-name")
	require.NoError(t, err)
	require.NotEqual(t, oldRevoked.KeyPEM, newRevoked.KeyPEM)

	oldExpired, err := pk.BuildClientFull("expired-name")
	require.NoError(t, err)
	oldExpiredSerial, err := oldExpired.Serial()
	require.NoError(t, err)
	require.NoError(t, pk.Expire("expired-name"))
	newExpired, err := pk.BuildClientFull("expired-name")
	require.NoError(t, err)
	require.NotEqual(t, oldExpired.KeyPEM, newExpired.KeyPEM)

	require.NoError(t, backend.View(func(components storage.Components) error {
		revokedHistory, err := components.Keys().GetBySerial(oldRevokedSerial)
		require.NoError(t, err)
		require.Equal(t, oldRevoked.KeyPEM, revokedHistory.KeyPEM)
		require.NotEqual(t, newRevoked.KeyPEM, revokedHistory.KeyPEM)
		expiredHistory, err := components.Keys().GetBySerial(oldExpiredSerial)
		require.NoError(t, err)
		require.Empty(t, expiredHistory.KeyPEM)
		return nil
	}))
}

func TestLifecycleArtifactFilesContainRegularCertificates(t *testing.T) {
	// Guard the test helpers themselves: lifecycle assertions must use actual
	// certificate PEM rather than merely checking path existence.
	t.Parallel()
	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	pair, err := pk.BuildClientFull("client")
	require.NoError(t, err)
	require.NoError(t, pk.Expire("client"))
	data, err := os.ReadFile(filepath.Join(pkiDir, "expired", "client.crt"))
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	_, err = x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, pair.CertPEM, data)
}

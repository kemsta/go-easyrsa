package pki_test

import (
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/legacy"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
)

func TestShowRenewedAcrossWritableBackends(t *testing.T) {
	for _, backendCase := range lifecycleBackends() {
		backendCase := backendCase
		t.Run(backendCase.name, func(t *testing.T) {
			t.Parallel()
			backend, _ := backendCase.create(t)
			pk := newLifecyclePKI(t, backend)
			valid, err := pk.BuildClientFull("valid", pki.WithNotAfter(time.Now().AddDate(1, 0, 0)))
			require.NoError(t, err)
			validSerial, err := valid.Serial()
			require.NoError(t, err)
			_, err = pk.Renew("valid")
			require.NoError(t, err)
			expired, err := pk.BuildClientFull(
				"expired",
				pki.WithNotBefore(time.Now().AddDate(-2, 0, 0)),
				pki.WithNotAfter(time.Now().AddDate(-1, 0, 0)),
			)
			require.NoError(t, err)
			expiredSerial, err := expired.Serial()
			require.NoError(t, err)
			_, err = pk.Renew("expired")
			require.NoError(t, err)

			results, err := pk.ShowRenewed()
			require.NoError(t, err)
			require.Len(t, results, 2)
			require.Equal(t, "valid", results[0].Name)
			require.Equal(t, "valid", results[0].CommonName)
			require.Equal(t, storage.StatusValid, results[0].Status)
			require.Zero(t, results[0].Serial.Cmp(validSerial))
			require.Equal(t, valid.CertPEM, results[0].CertificatePEM)
			require.False(t, results[0].RequiresRewind)
			require.Equal(t, "expired", results[1].Name)
			require.Equal(t, storage.StatusExpired, results[1].Status)
			require.Zero(t, results[1].Serial.Cmp(expiredSerial))
			require.Equal(t, expired.CertPEM, results[1].CertificatePEM)

			validEntry, err := pk.CheckSerial(validSerial)
			require.NoError(t, err)
			require.Equal(t, storage.StatusExpired, validEntry.Status, "renew keeps a safer internal superseded marker")

			results[0].Serial.SetInt64(999)
			results[0].CertificatePEM[0] ^= 0xff
			again, err := pk.ShowRenewed()
			require.NoError(t, err)
			require.Zero(t, again[0].Serial.Cmp(validSerial))
			require.Equal(t, valid.CertPEM, again[0].CertificatePEM)
		})
	}
}

func TestShowRenewedReportsHistoricalArchive(t *testing.T) {
	for _, backendCase := range lifecycleBackends() {
		backendCase := backendCase
		t.Run(backendCase.name, func(t *testing.T) {
			t.Parallel()
			backend, _ := backendCase.create(t)
			pk := newLifecyclePKI(t, backend)
			oldPair, err := pk.BuildClientFull("historical")
			require.NoError(t, err)
			oldSerial, err := oldPair.Serial()
			require.NoError(t, err)
			_, err = pk.Renew("historical")
			require.NoError(t, err)
			moveRenewalToHistoricalState(t, backend, "historical")

			results, err := pk.ShowRenewed()
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.Equal(t, "historical", results[0].Name)
			require.Equal(t, "historical", results[0].CommonName)
			require.Zero(t, results[0].Serial.Cmp(oldSerial))
			require.Equal(t, oldPair.CertPEM, results[0].CertificatePEM)
			require.True(t, results[0].RequiresRewind)
		})
	}
}

func TestShowRenewedUsesIndexCNForNamedArchives(t *testing.T) {
	t.Parallel()
	backend := memory.NewBackend()
	pk, err := pki.New(pki.Config{
		NoPass:           true,
		SequentialSerial: true,
		KeyAlgo:          pki.AlgoRSA,
		KeySize:          1024,
		DNMode:           pki.DNModeOrg,
		SubjTemplate:     pkix.Name{Organization: []string{"Acme"}},
	}, backend)
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.GenReq("storage-name")
	require.NoError(t, err)
	_, err = pk.SignReq("storage-name", cert.CertTypeClient, pki.WithSubjectOverride(pkix.Name{CommonName: "different-cn", Organization: []string{"Acme"}}))
	require.NoError(t, err)
	_, err = pk.Renew("storage-name")
	require.NoError(t, err)

	results, err := pk.ShowRenewed()
	require.NoError(t, err)
	require.Empty(t, results)
}

func TestShowRenewedOmitsRevokedIndexEntries(t *testing.T) {
	t.Parallel()
	backend := memory.NewBackend()
	pk := newLifecyclePKI(t, backend)
	oldPair, err := pk.BuildClientFull("client")
	require.NoError(t, err)
	oldSerial, err := oldPair.Serial()
	require.NoError(t, err)
	_, err = pk.Renew("client")
	require.NoError(t, err)
	require.NoError(t, backend.Update(func(components storage.Components) error {
		return components.Index().Update(oldSerial, storage.StatusRevoked, time.Now(), cert.ReasonUnspecified)
	}))

	results, err := pk.ShowRenewed()
	require.NoError(t, err)
	require.Empty(t, results)
}

func TestShowRenewedRejectsBothArchiveSources(t *testing.T) {
	t.Parallel()
	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	oldPair, err := pk.BuildClientFull("client")
	require.NoError(t, err)
	oldSerial, err := oldPair.Serial()
	require.NoError(t, err)
	_, err = pk.Renew("client")
	require.NoError(t, err)
	historicalDir := filepath.Join(pkiDir, "renewed", "certs_by_serial")
	require.NoError(t, os.MkdirAll(historicalDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(historicalDir, storage.HexSerial(oldSerial)+".crt"), oldPair.CertPEM, 0o644))

	_, err = pk.ShowRenewed()
	require.ErrorIs(t, err, storage.ErrConflict)
}

func TestShowRenewedValidatesUnmatchedArchives(t *testing.T) {
	t.Parallel()
	backend := memory.NewBackend()
	pk := newLifecyclePKI(t, backend)
	pair, err := pk.BuildClientFull("client")
	require.NoError(t, err)
	serial, err := pair.Serial()
	require.NoError(t, err)

	tests := []storage.RenewalArchive{
		{Name: "orphan", Serial: big.NewInt(999), CertificatePEM: []byte("broken"), Source: storage.RenewalArchiveIssued},
		{Name: "unmatched", Serial: new(big.Int).Add(serial, big.NewInt(1)), CertificatePEM: pair.CertPEM, Source: storage.RenewalArchiveIssued},
	}
	for _, archive := range tests {
		wrapped, err := pki.New(pki.Config{NoPass: true}, &renewalListBackend{Backend: backend, archives: []storage.RenewalArchive{archive}})
		require.NoError(t, err)
		_, err = wrapped.ShowRenewed()
		require.Error(t, err)
	}
}

func TestRevokeRenewedAcrossWritableBackends(t *testing.T) {
	for _, backendCase := range lifecycleBackends() {
		backendCase := backendCase
		t.Run(backendCase.name, func(t *testing.T) {
			t.Parallel()
			backend, pkiDir := backendCase.create(t)
			pk := newLifecyclePKI(t, backend)
			oldPair, err := pk.BuildClientFull("client")
			require.NoError(t, err)
			oldSerial, err := oldPair.Serial()
			require.NoError(t, err)
			currentPair, err := pk.Renew("client")
			require.NoError(t, err)
			currentSerial, err := currentPair.Serial()
			require.NoError(t, err)
			putDerivedArtifacts(t, backend, "client")
			currentKey, currentCSR := currentAssets(t, backend, "client")
			_, err = pk.GenCRL()
			require.NoError(t, err)
			crlBefore, err := pk.ShowCRL()
			require.NoError(t, err)

			require.NoError(t, pk.RevokeRenewed("client", cert.ReasonCertificateHold))
			requireDerivedArtifactsAbsent(t, backend, "client")
			currentAfter, err := pk.ShowCert("client")
			require.NoError(t, err)
			require.Equal(t, currentPair.CertPEM, currentAfter.CertPEM)
			require.Equal(t, currentPair.KeyPEM, currentAfter.KeyPEM)
			keyAfter, csrAfter := currentAssets(t, backend, "client")
			require.Equal(t, currentKey, keyAfter)
			require.Equal(t, currentCSR, csrAfter)
			oldEntry, err := pk.CheckSerial(oldSerial)
			require.NoError(t, err)
			require.Equal(t, storage.StatusRevoked, oldEntry.Status)
			require.Equal(t, cert.ReasonCertificateHold, oldEntry.RevocationReason)
			newEntry, err := pk.CheckSerial(currentSerial)
			require.NoError(t, err)
			require.Equal(t, storage.StatusValid, newEntry.Status)
			crlAfter, err := pk.ShowCRL()
			require.NoError(t, err)
			require.Equal(t, crlBefore.Raw, crlAfter.Raw)
			require.NoError(t, backend.View(func(components storage.Components) error {
				archives, err := components.Lifecycle().ListRenewed()
				require.NoError(t, err)
				require.Empty(t, archives)
				state, err := components.Lifecycle().ExportState()
				require.NoError(t, err)
				require.Len(t, state.Revoked, 1)
				require.Zero(t, state.Revoked[0].Serial.Cmp(oldSerial))
				return nil
			}))
			if pkiDir != "" {
				require.NoFileExists(t, filepath.Join(pkiDir, "renewed", "issued", "client.crt"))
				require.FileExists(t, filepath.Join(pkiDir, "revoked", "certs_by_serial", storage.HexSerial(oldSerial)+".crt"))
				require.FileExists(t, filepath.Join(pkiDir, "issued", "client.crt"))
				require.FileExists(t, filepath.Join(pkiDir, "private", "client.key"))
				require.FileExists(t, filepath.Join(pkiDir, "reqs", "client.req"))
			}

			_, err = pk.GenCRL()
			require.NoError(t, err)
			crl, err := pk.ShowCRL()
			require.NoError(t, err)
			require.Len(t, crl.RevokedCertificateEntries, 1)
			require.Equal(t, int(cert.ReasonCertificateHold), crl.RevokedCertificateEntries[0].ReasonCode)
			_, err = pk.Renew("client")
			require.NoError(t, err, "revoking the old archive must free the renewal slot")
		})
	}
}

func TestRevokeRenewedRejectsHistoricalArchive(t *testing.T) {
	t.Parallel()
	backend := memory.NewBackend()
	pk := newLifecyclePKI(t, backend)
	_, err := pk.BuildClientFull("historical")
	require.NoError(t, err)
	_, err = pk.Renew("historical")
	require.NoError(t, err)
	moveRenewalToHistoricalState(t, backend, "historical")

	err = pk.RevokeRenewed("historical", cert.ReasonUnspecified)
	require.ErrorIs(t, err, storage.ErrNotFound)
	results, err := pk.ShowRenewed()
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].RequiresRewind)
}

func TestRevokeRenewedRollsBackIndexAndArtifactFailures(t *testing.T) {
	t.Parallel()

	t.Run("index", func(t *testing.T) {
		backend := memory.NewBackend()
		good := newLifecyclePKI(t, backend)
		oldPair, err := good.BuildClientFull("client")
		require.NoError(t, err)
		oldSerial, err := oldPair.Serial()
		require.NoError(t, err)
		_, err = good.Renew("client")
		require.NoError(t, err)
		updateErr := errors.New("index update failed")
		failing, err := pki.New(pki.Config{NoPass: true}, &indexUpdateFailureBackend{Backend: backend, err: updateErr})
		require.NoError(t, err)

		err = failing.RevokeRenewed("client", cert.ReasonUnspecified)
		require.ErrorIs(t, err, updateErr)
		assertRenewalStillPresent(t, good, oldSerial)
	})

	t.Run("artifact", func(t *testing.T) {
		backend := memory.NewBackend()
		good := newLifecyclePKI(t, backend)
		oldPair, err := good.BuildClientFull("client")
		require.NoError(t, err)
		oldSerial, err := oldPair.Serial()
		require.NoError(t, err)
		_, err = good.Renew("client")
		require.NoError(t, err)
		putDerivedArtifacts(t, backend, "client")
		before, err := good.ShowCert("client")
		require.NoError(t, err)
		beforeKey, beforeCSR := currentAssets(t, backend, "client")
		deleteErr := errors.New("artifact delete failed")
		failing, err := pki.New(pki.Config{NoPass: true}, &partialArtifactDeleteFailureBackend{Backend: backend, err: deleteErr, failAfter: 2})
		require.NoError(t, err)

		err = failing.RevokeRenewed("client", cert.ReasonUnspecified)
		require.ErrorIs(t, err, deleteErr)
		assertRenewalStillPresent(t, good, oldSerial)
		assertAllDerivedArtifactsPresent(t, backend, "client")
		after, err := good.ShowCert("client")
		require.NoError(t, err)
		require.Equal(t, before.CertPEM, after.CertPEM)
		afterKey, afterCSR := currentAssets(t, backend, "client")
		require.Equal(t, beforeKey, afterKey)
		require.Equal(t, beforeCSR, afterCSR)
	})

	t.Run("post mutation callback", func(t *testing.T) {
		backend := memory.NewBackend()
		good := newLifecyclePKI(t, backend)
		oldPair, err := good.BuildClientFull("client")
		require.NoError(t, err)
		oldSerial, err := oldPair.Serial()
		require.NoError(t, err)
		_, err = good.Renew("client")
		require.NoError(t, err)
		putDerivedArtifacts(t, backend, "client")
		callbackErr := errors.New("post mutation failure")
		failing, err := pki.New(pki.Config{NoPass: true}, &postMutationFailureBackend{Backend: backend, err: callbackErr})
		require.NoError(t, err)

		err = failing.RevokeRenewed("client", cert.ReasonUnspecified)
		require.ErrorIs(t, err, callbackErr)
		assertRenewalStillPresent(t, good, oldSerial)
		assertAllDerivedArtifactsPresent(t, backend, "client")
	})
}

func TestRevokeRenewedRejectsDestinationConflict(t *testing.T) {
	t.Parallel()
	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	oldPair, err := pk.BuildClientFull("client")
	require.NoError(t, err)
	oldSerial, err := oldPair.Serial()
	require.NoError(t, err)
	_, err = pk.Renew("client")
	require.NoError(t, err)
	destination := filepath.Join(pkiDir, "revoked", "certs_by_serial", storage.HexSerial(oldSerial)+".crt")
	require.NoError(t, os.MkdirAll(filepath.Dir(destination), 0o755))
	require.NoError(t, os.WriteFile(destination, []byte("occupied"), 0o644))

	err = pk.RevokeRenewed("client", cert.ReasonUnspecified)
	require.ErrorIs(t, err, storage.ErrConflict)
	require.FileExists(t, filepath.Join(pkiDir, "renewed", "issued", "client.crt"))
	entry, err := pk.CheckSerial(oldSerial)
	require.NoError(t, err)
	require.Equal(t, storage.StatusExpired, entry.Status)
}

func TestRenewedMethodsRejectInvalidAndReadOnlyInputs(t *testing.T) {
	t.Parallel()
	backend := memory.NewBackend()
	pk := newLifecyclePKI(t, backend)
	ca, err := pk.ShowCA()
	require.NoError(t, err)
	caSerial, err := ca.Serial()
	require.NoError(t, err)
	require.NoError(t, backend.Update(func(components storage.Components) error {
		return components.Lifecycle().ReplaceState(storage.LifecycleState{Renewed: []storage.LifecycleRecord{{
			Name:           "ca",
			Serial:         caSerial,
			CertificatePEM: ca.CertPEM,
			RenewalSource:  storage.RenewalArchiveIssued,
		}}})
	}))
	require.Error(t, pk.RevokeRenewed("ca", cert.ReasonUnspecified))
	require.Error(t, pk.RevokeRenewed("../escape", cert.ReasonUnspecified))
	require.Error(t, pk.RevokeRenewed("ca", cert.RevocationReason(99)))

	legacyDir := t.TempDir()
	fixture := testutil.WriteLegacyFixture(t, legacyDir)
	require.NoError(t, os.MkdirAll(filepath.Join(legacyDir, "renewed", "issued"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(legacyDir, "renewed", "issued", "client1.crt"), fixture.ClientOld.CertPEM, 0o644))
	legacyPKI, err := pki.New(pki.Config{CAName: fixture.CAPair.Name}, legacy.NewBackend(legacyDir, fixture.CAPair.Name))
	require.NoError(t, err)
	results, err := legacyPKI.ShowRenewed()
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.ErrorIs(t, legacyPKI.RevokeRenewed("client1", cert.ReasonUnspecified), storage.ErrReadOnly)
}

func TestFilesystemIndexRoundTripsEveryRevocationReason(t *testing.T) {
	t.Parallel()
	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	reasons := []cert.RevocationReason{
		cert.ReasonUnspecified,
		cert.ReasonKeyCompromise,
		cert.ReasonCACompromise,
		cert.ReasonAffiliationChanged,
		cert.ReasonSuperseded,
		cert.ReasonCessationOfOperation,
		cert.ReasonCertificateHold,
	}
	for i, reason := range reasons {
		name := "client-" + big.NewInt(int64(i)).String()
		pair, err := pk.BuildClientFull(name)
		require.NoError(t, err)
		serial, err := pair.Serial()
		require.NoError(t, err)
		require.NoError(t, pk.RevokeIssued(name, reason))
		reopened, err := pki.OpenWithFS(pkiDir, pki.Config{NoPass: true})
		require.NoError(t, err)
		entry, err := reopened.CheckSerial(serial)
		require.NoError(t, err)
		require.Equal(t, reason, entry.RevocationReason)
	}
}

type renewalListBackend struct {
	storage.Backend
	archives []storage.RenewalArchive
}

func (b *renewalListBackend) View(fn func(storage.Components) error) error {
	return b.Backend.View(func(components storage.Components) error {
		return fn(renewalListComponents{Components: components, archives: b.archives})
	})
}

type renewalListComponents struct {
	storage.Components
	archives []storage.RenewalArchive
}

func (c renewalListComponents) Lifecycle() storage.LifecycleStorage {
	return renewalListStorage{LifecycleStorage: c.Components.Lifecycle(), archives: c.archives}
}

type renewalListStorage struct {
	storage.LifecycleStorage
	archives []storage.RenewalArchive
}

func (s renewalListStorage) ListRenewed() ([]storage.RenewalArchive, error) {
	archives := make([]storage.RenewalArchive, len(s.archives))
	for i, archive := range s.archives {
		archives[i] = archive
		if archive.Serial != nil {
			archives[i].Serial = new(big.Int).Set(archive.Serial)
		}
		archives[i].CertificatePEM = append([]byte(nil), archive.CertificatePEM...)
	}
	return archives, nil
}

type partialArtifactDeleteFailureBackend struct {
	storage.Backend
	err       error
	failAfter int
}

func (b *partialArtifactDeleteFailureBackend) Update(fn func(storage.Components) error) error {
	return b.Backend.Update(func(components storage.Components) error {
		deleted := 0
		return fn(partialArtifactDeleteFailureComponents{
			Components: components,
			err:        b.err,
			failAfter:  b.failAfter,
			deleted:    &deleted,
		})
	})
}

type partialArtifactDeleteFailureComponents struct {
	storage.Components
	err       error
	failAfter int
	deleted   *int
}

func (c partialArtifactDeleteFailureComponents) Artifacts() storage.ArtifactStorage {
	return partialArtifactDeleteFailureStorage{
		ArtifactStorage: c.Components.Artifacts(),
		err:             c.err,
		failAfter:       c.failAfter,
		deleted:         c.deleted,
	}
}

type partialArtifactDeleteFailureStorage struct {
	storage.ArtifactStorage
	err       error
	failAfter int
	deleted   *int
}

func (s partialArtifactDeleteFailureStorage) DeleteArtifact(name string) error {
	if *s.deleted == s.failAfter {
		return s.err
	}
	if err := s.ArtifactStorage.DeleteArtifact(name); err != nil {
		return err
	}
	(*s.deleted)++
	return nil
}

type postMutationFailureBackend struct {
	storage.Backend
	err error
}

func (b *postMutationFailureBackend) Update(fn func(storage.Components) error) error {
	return b.Backend.Update(func(components storage.Components) error {
		if err := fn(components); err != nil {
			return err
		}
		return b.err
	})
}

func assertAllDerivedArtifactsPresent(t *testing.T, backend storage.Backend, name string) {
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
			require.NoError(t, err, artifactPath)
		}
		return nil
	}))
}

func moveRenewalToHistoricalState(t *testing.T, backend storage.Backend, name string) {
	t.Helper()
	var state storage.LifecycleState
	require.NoError(t, backend.View(func(components storage.Components) error {
		var err error
		state, err = components.Lifecycle().ExportState()
		return err
	}))
	found := false
	for i := range state.Renewed {
		if state.Renewed[i].Name != name {
			continue
		}
		state.Renewed[i].RenewalSource = storage.RenewalArchiveBySerial
		state.Renewed[i].PrivateKeyPEM = nil
		state.Renewed[i].CSRPEM = nil
		found = true
	}
	require.True(t, found)
	require.NoError(t, backend.Update(func(components storage.Components) error {
		return components.Lifecycle().ReplaceState(state)
	}))
}

func currentAssets(t *testing.T, backend storage.Backend, name string) ([]byte, []byte) {
	t.Helper()
	var key, csr []byte
	require.NoError(t, backend.View(func(components storage.Components) error {
		var err error
		key, err = components.Keys().GetPrivateKey(name)
		if err != nil {
			return err
		}
		csr, err = components.CSRs().GetCSR(name)
		return err
	}))
	return append([]byte(nil), key...), append([]byte(nil), csr...)
}

func assertRenewalStillPresent(t *testing.T, pk *pki.PKI, serial *big.Int) {
	t.Helper()
	results, err := pk.ShowRenewed()
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Zero(t, results[0].Serial.Cmp(serial))
	entry, err := pk.CheckSerial(serial)
	require.NoError(t, err)
	require.Equal(t, storage.StatusExpired, entry.Status)
}

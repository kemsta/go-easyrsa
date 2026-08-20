package legacy_test

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/legacy"
)

func TestBackendListsBothRenewalArchiveSources(t *testing.T) {
	t.Parallel()
	pkiDir, namedPEM, namedSerial, historicalPEM, historicalSerial := legacyRenewalArchiveFixture(t)
	backend := legacy.NewBackend(pkiDir, "ca")

	require.NoError(t, backend.View(func(components storage.Components) error {
		archives, err := components.Lifecycle().ListRenewed()
		require.NoError(t, err)
		require.Len(t, archives, 2)
		require.Equal(t, "named", archives[0].Name)
		require.Equal(t, storage.RenewalArchiveIssued, archives[0].Source)
		require.Zero(t, archives[0].Serial.Cmp(namedSerial))
		require.Equal(t, namedPEM, archives[0].CertificatePEM)
		require.Empty(t, archives[1].Name)
		require.Equal(t, storage.RenewalArchiveBySerial, archives[1].Source)
		require.Zero(t, archives[1].Serial.Cmp(historicalSerial))
		require.Equal(t, historicalPEM, archives[1].CertificatePEM)
		archives[0].Serial.SetInt64(999)
		archives[0].CertificatePEM[0] ^= 0xff

		state, err := components.Lifecycle().ExportState()
		require.NoError(t, err)
		require.Len(t, state.Renewed, 2)
		require.Equal(t, storage.RenewalArchiveIssued, state.Renewed[0].RenewalSource)
		require.Equal(t, storage.RenewalArchiveBySerial, state.Renewed[1].RenewalSource)
		return nil
	}))

	require.NoError(t, backend.View(func(components storage.Components) error {
		archives, err := components.Lifecycle().ListRenewed()
		require.NoError(t, err)
		require.Zero(t, archives[0].Serial.Cmp(namedSerial))
		require.Equal(t, namedPEM, archives[0].CertificatePEM)
		return nil
	}))
	require.ErrorIs(t, backend.Update(func(storage.Components) error { return nil }), storage.ErrReadOnly)
}

func TestBackendListRenewedRejectsUnsafeCertificate(t *testing.T) {
	t.Parallel()

	t.Run("leaf symlink", func(t *testing.T) {
		pkiDir, namedPEM, _, _, _ := legacyRenewalArchiveFixture(t)
		require.NoError(t, os.Remove(filepath.Join(pkiDir, "renewed", "issued", "named.crt")))
		outside := filepath.Join(t.TempDir(), "outside.crt")
		require.NoError(t, os.WriteFile(outside, namedPEM, 0o644))
		require.NoError(t, os.Symlink(outside, filepath.Join(pkiDir, "renewed", "issued", "named.crt")))

		backend := legacy.NewBackend(pkiDir, "ca")
		err := backend.View(func(components storage.Components) error {
			_, err := components.Lifecycle().ListRenewed()
			return err
		})
		require.Error(t, err)
	})

	t.Run("archive directory symlink", func(t *testing.T) {
		pkiDir, namedPEM, _, _, _ := legacyRenewalArchiveFixture(t)
		require.NoError(t, os.RemoveAll(filepath.Join(pkiDir, "renewed", "issued")))
		outside := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(outside, "named.crt"), namedPEM, 0o644))
		require.NoError(t, os.Symlink(outside, filepath.Join(pkiDir, "renewed", "issued")))

		backend := legacy.NewBackend(pkiDir, "ca")
		err := backend.View(func(components storage.Components) error {
			_, err := components.Lifecycle().ListRenewed()
			return err
		})
		require.Error(t, err)
	})

	t.Run("renewed parent symlink", func(t *testing.T) {
		pkiDir, namedPEM, _, _, _ := legacyRenewalArchiveFixture(t)
		require.NoError(t, os.RemoveAll(filepath.Join(pkiDir, "renewed")))
		outside := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(outside, "issued"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(outside, "issued", "named.crt"), namedPEM, 0o644))
		require.NoError(t, os.Symlink(outside, filepath.Join(pkiDir, "renewed")))

		backend := legacy.NewBackend(pkiDir, "ca")
		err := backend.View(func(components storage.Components) error {
			_, err := components.Lifecycle().ListRenewed()
			return err
		})
		require.Error(t, err)
	})
}

func legacyRenewalArchiveFixture(t *testing.T) (string, []byte, *big.Int, []byte, *big.Int) {
	t.Helper()
	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	named, err := pk.BuildClientFull("named")
	require.NoError(t, err)
	namedSerial, err := named.Serial()
	require.NoError(t, err)
	_, err = pk.Renew("named")
	require.NoError(t, err)
	historical, err := pk.BuildClientFull("historical")
	require.NoError(t, err)
	historicalSerial, err := historical.Serial()
	require.NoError(t, err)
	_, err = pk.Renew("historical")
	require.NoError(t, err)

	historicalDir := filepath.Join(pkiDir, "renewed", "certs_by_serial")
	require.NoError(t, os.MkdirAll(historicalDir, 0o755))
	require.NoError(t, os.Rename(
		filepath.Join(pkiDir, "renewed", "issued", "historical.crt"),
		filepath.Join(historicalDir, storage.HexSerial(historicalSerial)+".crt"),
	))
	return pkiDir, append([]byte(nil), named.CertPEM...), new(big.Int).Set(namedSerial), append([]byte(nil), historical.CertPEM...), new(big.Int).Set(historicalSerial)
}

package memory_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
)

func TestLifecycleListRenewedPreservesSourcesAndCopies(t *testing.T) {
	t.Parallel()
	backend, namedPEM, namedSerial, historicalPEM, historicalSerial := memoryRenewalArchiveFixture(t)

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
		return nil
	}))

	require.NoError(t, backend.View(func(components storage.Components) error {
		archives, err := components.Lifecycle().ListRenewed()
		require.NoError(t, err)
		require.Zero(t, archives[0].Serial.Cmp(namedSerial))
		require.Equal(t, namedPEM, archives[0].CertificatePEM)
		return nil
	}))
}

func TestLifecycleReplaceStateTreatsEmptyRenewalSourceAsNamed(t *testing.T) {
	t.Parallel()
	backend, namedPEM, namedSerial, _, _ := memoryRenewalArchiveFixture(t)
	require.NoError(t, backend.Update(func(components storage.Components) error {
		return components.Lifecycle().ReplaceState(storage.LifecycleState{Renewed: []storage.LifecycleRecord{{
			Name:           "named",
			Serial:         new(big.Int).Set(namedSerial),
			CertificatePEM: append([]byte(nil), namedPEM...),
		}}})
	}))
	require.NoError(t, backend.View(func(components storage.Components) error {
		archives, err := components.Lifecycle().ListRenewed()
		require.NoError(t, err)
		require.Len(t, archives, 1)
		require.Equal(t, storage.RenewalArchiveIssued, archives[0].Source)
		return nil
	}))
}

func TestLifecycleReplaceStateRejectsDuplicateAndInvalidRenewalSources(t *testing.T) {
	t.Parallel()
	backend, namedPEM, namedSerial, _, _ := memoryRenewalArchiveFixture(t)
	base := storage.LifecycleRecord{Name: "named", Serial: new(big.Int).Set(namedSerial), CertificatePEM: append([]byte(nil), namedPEM...)}

	duplicate := base
	duplicate.Name = "duplicate"
	duplicate.RenewalSource = storage.RenewalArchiveBySerial
	err := backend.Update(func(components storage.Components) error {
		return components.Lifecycle().ReplaceState(storage.LifecycleState{Renewed: []storage.LifecycleRecord{base, duplicate}})
	})
	require.ErrorIs(t, err, storage.ErrConflict)

	invalid := base
	invalid.RenewalSource = "invalid"
	err = backend.Update(func(components storage.Components) error {
		return components.Lifecycle().ReplaceState(storage.LifecycleState{Renewed: []storage.LifecycleRecord{invalid}})
	})
	require.Error(t, err)

	historicalWithKey := base
	historicalWithKey.RenewalSource = storage.RenewalArchiveBySerial
	historicalWithKey.PrivateKeyPEM = []byte("key")
	err = backend.Update(func(components storage.Components) error {
		return components.Lifecycle().ReplaceState(storage.LifecycleState{Renewed: []storage.LifecycleRecord{historicalWithKey}})
	})
	require.Error(t, err)

	historicalWithWrongName := base
	historicalWithWrongName.Name = "different-name"
	historicalWithWrongName.RenewalSource = storage.RenewalArchiveBySerial
	err = backend.Update(func(components storage.Components) error {
		return components.Lifecycle().ReplaceState(storage.LifecycleState{Renewed: []storage.LifecycleRecord{historicalWithWrongName}})
	})
	require.Error(t, err)
}

func TestMovingNamedRenewalLeavesHistoricalArchive(t *testing.T) {
	t.Parallel()
	backend, _, namedSerial, historicalPEM, historicalSerial := memoryRenewalArchiveFixture(t)
	require.NoError(t, backend.Update(func(components storage.Components) error {
		return components.Lifecycle().MoveRenewedToRevoked("named", namedSerial)
	}))
	require.NoError(t, backend.View(func(components storage.Components) error {
		archives, err := components.Lifecycle().ListRenewed()
		require.NoError(t, err)
		require.Len(t, archives, 1)
		require.Equal(t, storage.RenewalArchiveBySerial, archives[0].Source)
		require.Zero(t, archives[0].Serial.Cmp(historicalSerial))
		require.Equal(t, historicalPEM, archives[0].CertificatePEM)
		return nil
	}))
}

func TestLifecycleHistoricalStateRollsBackWithUpdate(t *testing.T) {
	t.Parallel()
	backend, _, _, _, _ := memoryRenewalArchiveFixture(t)
	var before storage.LifecycleState
	require.NoError(t, backend.View(func(components storage.Components) error {
		var err error
		before, err = components.Lifecycle().ExportState()
		return err
	}))
	rollbackErr := errors.New("rollback")
	err := backend.Update(func(components storage.Components) error {
		require.NoError(t, components.Lifecycle().ReplaceState(storage.LifecycleState{}))
		return rollbackErr
	})
	require.ErrorIs(t, err, rollbackErr)
	require.NoError(t, backend.View(func(components storage.Components) error {
		after, err := components.Lifecycle().ExportState()
		require.NoError(t, err)
		require.Equal(t, before, after)
		return nil
	}))
}

func memoryRenewalArchiveFixture(t *testing.T) (*memory.Backend, []byte, *big.Int, []byte, *big.Int) {
	t.Helper()
	backend := memory.NewBackend()
	pk, err := pki.New(pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024}, backend)
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

	var state storage.LifecycleState
	require.NoError(t, backend.View(func(components storage.Components) error {
		var err error
		state, err = components.Lifecycle().ExportState()
		return err
	}))
	require.Len(t, state.Renewed, 2)
	for i := range state.Renewed {
		if state.Renewed[i].Name != "historical" {
			continue
		}
		state.Renewed[i].RenewalSource = storage.RenewalArchiveBySerial
		state.Renewed[i].PrivateKeyPEM = nil
		state.Renewed[i].CSRPEM = nil
	}
	require.NoError(t, backend.Update(func(components storage.Components) error {
		return components.Lifecycle().ReplaceState(state)
	}))
	return backend, append([]byte(nil), named.CertPEM...), new(big.Int).Set(namedSerial), append([]byte(nil), historical.CertPEM...), new(big.Int).Set(historicalSerial)
}

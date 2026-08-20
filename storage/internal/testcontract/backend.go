package testcontract

import (
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

// WritableBackendFactory returns a fresh writable backend for each contract
// subtest.
type WritableBackendFactory func(t *testing.T) storage.Backend

// RunWritableBackend exercises behavior shared by all writable backends.
func RunWritableBackend(t *testing.T, factory WritableBackendFactory) {
	t.Helper()

	t.Run("commit_and_read_only_view", func(t *testing.T) {
		backend := factory(t)
		require.False(t, backend.ReadOnly())
		require.NoError(t, backend.EnsureLayout())
		input := []byte("artifact")
		require.NoError(t, backend.Update(func(components storage.Components) error {
			require.NoError(t, components.CSRs().PutCSR("client", []byte("request")))
			require.NoError(t, components.Index().Record(storage.IndexEntry{
				Status: storage.StatusValid,
				Serial: big.NewInt(7),
			}))
			return components.Artifacts().PutArtifact(storage.Artifact{
				Path:       "private/client.p12",
				Data:       input,
				Visibility: storage.ArtifactPrivate,
			})
		}))
		input[0] = 'X'

		require.NoError(t, backend.View(func(components storage.Components) error {
			csr, err := components.CSRs().GetCSR("client")
			require.NoError(t, err)
			require.Equal(t, []byte("request"), csr)
			artifact, err := components.Artifacts().GetArtifact("private/client.p12")
			require.NoError(t, err)
			require.Equal(t, []byte("artifact"), artifact.Data)
			entries, err := components.Index().Query(storage.IndexFilter{})
			require.NoError(t, err)
			require.Len(t, entries, 1)
			require.Equal(t, big.NewInt(7), entries[0].Serial)
			require.ErrorIs(t, components.CSRs().PutCSR("blocked", []byte("value")), storage.ErrReadOnly)
			require.ErrorIs(t, components.Artifacts().DeleteArtifact("private/client.p12"), storage.ErrReadOnly)
			_, err = components.Serials().Next()
			require.ErrorIs(t, err, storage.ErrReadOnly)
			return nil
		}))
	})

	t.Run("callback_error_rolls_back_all_facets", func(t *testing.T) {
		backend := factory(t)
		require.NoError(t, backend.EnsureLayout())
		callbackErr := errors.New("rollback")
		err := backend.Update(func(components storage.Components) error {
			require.NoError(t, components.CSRs().PutCSR("client", []byte("request")))
			require.NoError(t, components.Artifacts().PutArtifact(storage.Artifact{
				Path:       "crl.pem",
				Data:       []byte("crl"),
				Visibility: storage.ArtifactPublic,
			}))
			require.NoError(t, components.Index().Record(storage.IndexEntry{
				Status: storage.StatusValid,
				Serial: big.NewInt(9),
			}))
			return callbackErr
		})
		require.ErrorIs(t, err, callbackErr)
		require.NoError(t, backend.View(func(components storage.Components) error {
			_, err := components.CSRs().GetCSR("client")
			require.ErrorIs(t, err, storage.ErrNotFound)
			_, err = components.Artifacts().GetArtifact("crl.pem")
			require.ErrorIs(t, err, storage.ErrNotFound)
			entries, err := components.Index().Query(storage.IndexFilter{})
			require.NoError(t, err)
			require.Empty(t, entries)
			return nil
		}))
	})

	t.Run("initialize_requires_explicit_reset", func(t *testing.T) {
		backend := factory(t)
		require.NoError(t, backend.EnsureLayout())
		require.NoError(t, backend.Update(func(components storage.Components) error {
			return components.CSRs().PutCSR("client", []byte("request"))
		}))
		require.ErrorIs(t, backend.Initialize(false), storage.ErrConflict)
		require.NoError(t, backend.Initialize(true))
		require.NoError(t, backend.View(func(components storage.Components) error {
			_, err := components.CSRs().GetCSR("client")
			require.ErrorIs(t, err, storage.ErrNotFound)
			return nil
		}))
	})
}

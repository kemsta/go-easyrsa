package testcontract

import (
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
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

	t.Run("lifecycle_locations", func(t *testing.T) {
		backend := factory(t)
		require.NoError(t, backend.EnsureLayout())
		require.NoError(t, backend.Update(func(components storage.Components) error {
			if err := components.Keys().Put(&cert.Pair{Name: "expired", CertPEM: []byte("expired-cert"), KeyPEM: []byte("key")}); err != nil {
				return err
			}
			if err := components.CSRs().PutCSR("expired", []byte("request")); err != nil {
				return err
			}
			return components.Lifecycle().MoveIssuedToExpired("expired", big.NewInt(7))
		}))
		require.NoError(t, backend.View(func(components storage.Components) error {
			certificate, err := components.Lifecycle().GetExpiredCertificate("expired")
			require.NoError(t, err)
			require.Equal(t, []byte("expired-cert"), certificate)
			return nil
		}))
		require.NoError(t, backend.Update(func(components storage.Components) error {
			return components.Lifecycle().MoveExpiredToRevoked("expired", big.NewInt(7))
		}))
		require.NoError(t, backend.View(func(components storage.Components) error {
			_, err := components.Lifecycle().GetExpiredCertificate("expired")
			require.ErrorIs(t, err, storage.ErrNotFound)
			_, err = components.Keys().GetPrivateKey("expired")
			require.NoError(t, err)
			_, err = components.CSRs().GetCSR("expired")
			return err
		}))

		require.NoError(t, backend.Update(func(components storage.Components) error {
			if err := components.Keys().Put(&cert.Pair{Name: "renewed", CertPEM: []byte("renewed-cert"), KeyPEM: []byte("key")}); err != nil {
				return err
			}
			return components.Lifecycle().MoveIssuedToRenewed("renewed", big.NewInt(9))
		}))
		require.NoError(t, backend.View(func(components storage.Components) error {
			certificate, err := components.Lifecycle().GetRenewedCertificate("renewed")
			require.NoError(t, err)
			require.Equal(t, []byte("renewed-cert"), certificate)
			return nil
		}))
		err := backend.Update(func(components storage.Components) error {
			return components.Lifecycle().MoveIssuedToRenewed("renewed", big.NewInt(9))
		})
		require.ErrorIs(t, err, storage.ErrConflict)

		require.NoError(t, backend.Update(func(components storage.Components) error {
			if err := components.Keys().Put(&cert.Pair{Name: "issued", CertPEM: []byte("issued-cert"), KeyPEM: []byte("key")}); err != nil {
				return err
			}
			if err := components.CSRs().PutCSR("issued", []byte("request")); err != nil {
				return err
			}
			return components.Lifecycle().MoveIssuedToRevoked("issued", big.NewInt(8))
		}))
		require.NoError(t, backend.View(func(components storage.Components) error {
			_, err := components.Keys().GetPrivateKey("issued")
			require.ErrorIs(t, err, storage.ErrNotFound)
			_, err = components.CSRs().GetCSR("issued")
			require.ErrorIs(t, err, storage.ErrNotFound)
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

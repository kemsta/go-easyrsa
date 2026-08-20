package memory_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	certpkg "github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/internal/testcontract"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
)

func TestBackendWritableContract(t *testing.T) {
	t.Parallel()
	testcontract.RunWritableBackend(t, func(t *testing.T) storage.Backend {
		t.Helper()
		return memory.NewBackend()
	})
}

func TestBackendUpdateCommitsAtomically(t *testing.T) {
	t.Parallel()

	backend := memory.NewBackend()
	require.NoError(t, backend.Update(func(components storage.Components) error {
		require.NoError(t, components.CSRs().PutCSR("client", []byte("request")))
		require.NoError(t, components.Artifacts().PutArtifact(storage.Artifact{
			Path:       "private/client.p12",
			Data:       []byte("archive"),
			Visibility: storage.ArtifactPrivate,
		}))
		_, err := components.Serials().Next()
		return err
	}))

	require.NoError(t, backend.View(func(components storage.Components) error {
		csr, err := components.CSRs().GetCSR("client")
		require.NoError(t, err)
		require.Equal(t, []byte("request"), csr)
		artifact, err := components.Artifacts().GetArtifact("private/client.p12")
		require.NoError(t, err)
		require.Equal(t, []byte("archive"), artifact.Data)
		_, err = components.Serials().Next()
		require.ErrorIs(t, err, storage.ErrReadOnly)
		return nil
	}))
	require.NoError(t, backend.Update(func(components storage.Components) error {
		next, err := components.Serials().Next()
		require.NoError(t, err)
		require.Equal(t, big.NewInt(2), next)
		return nil
	}))

	// A read view rejects mutations.
	require.NoError(t, backend.View(func(components storage.Components) error {
		require.ErrorIs(t, components.CSRs().PutCSR("discarded", []byte("value")), storage.ErrReadOnly)
		return nil
	}))
	require.NoError(t, backend.View(func(components storage.Components) error {
		_, err := components.CSRs().GetCSR("discarded")
		require.ErrorIs(t, err, storage.ErrNotFound)
		return nil
	}))
}

func TestBackendUpdateRollsBackCallbackError(t *testing.T) {
	t.Parallel()

	backend := memory.NewBackend()
	callbackErr := errors.New("stop")
	err := backend.Update(func(components storage.Components) error {
		require.NoError(t, components.CSRs().PutCSR("client", []byte("request")))
		require.NoError(t, components.Index().Record(storage.IndexEntry{
			Status: storage.StatusValid,
			Serial: big.NewInt(42),
		}))
		return callbackErr
	})
	require.ErrorIs(t, err, callbackErr)

	require.NoError(t, backend.View(func(components storage.Components) error {
		_, err := components.CSRs().GetCSR("client")
		require.ErrorIs(t, err, storage.ErrNotFound)
		entries, err := components.Index().Query(storage.IndexFilter{})
		require.NoError(t, err)
		require.Empty(t, entries)
		return nil
	}))
}

func TestBackendReturnsDeepCopies(t *testing.T) {
	t.Parallel()

	backend := memory.NewBackend()
	input := []byte("request")
	require.NoError(t, backend.Update(func(components storage.Components) error {
		require.NoError(t, components.CSRs().PutCSR("client", input))
		return components.Index().Record(storage.IndexEntry{
			Status: storage.StatusValid,
			Serial: big.NewInt(9),
			Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{
				Type:  asn1.ObjectIdentifier{1, 2, 3, 4},
				Value: []byte("mutable"),
			}}},
		})
	}))
	input[0] = 'X'

	require.NoError(t, backend.View(func(components storage.Components) error {
		csr, err := components.CSRs().GetCSR("client")
		require.NoError(t, err)
		csr[0] = 'Y'
		entries, err := components.Index().Query(storage.IndexFilter{})
		require.NoError(t, err)
		entries[0].Serial.SetInt64(100)
		entries[0].Subject.ExtraNames[0].Type[0] = 9
		entries[0].Subject.ExtraNames[0].Value.([]byte)[0] = 'X'
		return nil
	}))

	require.NoError(t, backend.View(func(components storage.Components) error {
		csr, err := components.CSRs().GetCSR("client")
		require.NoError(t, err)
		require.Equal(t, []byte("request"), csr)
		entries, err := components.Index().Query(storage.IndexFilter{})
		require.NoError(t, err)
		require.Equal(t, big.NewInt(9), entries[0].Serial)
		require.Equal(t, asn1.ObjectIdentifier{1, 2, 3, 4}, entries[0].Subject.ExtraNames[0].Type)
		require.Equal(t, []byte("mutable"), entries[0].Subject.ExtraNames[0].Value)
		return nil
	}))
}

func TestBackendReissueUsesPendingKeyAfterRevocation(t *testing.T) {
	t.Parallel()

	backend := memory.NewBackend()
	pk, err := pki.New(pki.Config{NoPass: true, SequentialSerial: true}, backend)
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	oldPair, err := pk.BuildClientFull("client")
	require.NoError(t, err)
	oldSerial, err := oldPair.Serial()
	require.NoError(t, err)
	require.NoError(t, backend.Update(func(components storage.Components) error {
		return components.Lifecycle().MoveIssuedToRevoked("client", oldSerial)
	}))

	_, err = pk.GenReq("client")
	require.NoError(t, err)
	request, err := pk.ShowReq("client")
	require.NoError(t, err)
	parsedRequest, err := request.Request()
	require.NoError(t, err)
	newPair, err := pk.SignReq("client", certpkg.CertTypeClient)
	require.NoError(t, err)
	certificate, err := newPair.Certificate()
	require.NoError(t, err)
	requestPublic, err := x509.MarshalPKIXPublicKey(parsedRequest.PublicKey)
	require.NoError(t, err)
	certificatePublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	require.NoError(t, err)
	require.Equal(t, requestPublic, certificatePublic)
	require.NotEmpty(t, newPair.KeyPEM)
}

func TestBackendRejectsInvalidArtifactVisibility(t *testing.T) {
	t.Parallel()

	backend := memory.NewBackend()
	err := backend.Update(func(components storage.Components) error {
		return components.Artifacts().PutArtifact(storage.Artifact{
			Path:       "artifact.pem",
			Data:       []byte("data"),
			Visibility: storage.ArtifactVisibility(99),
		})
	})
	require.Error(t, err)
}

func TestBackendInitializeRequiresReset(t *testing.T) {
	t.Parallel()

	backend := memory.NewBackend()
	require.NoError(t, backend.Update(func(components storage.Components) error {
		return components.CSRs().PutCSR("client", []byte("request"))
	}))

	require.ErrorIs(t, backend.Initialize(false), storage.ErrConflict)
	require.NoError(t, backend.Initialize(true))
	empty, err := backend.Empty()
	require.NoError(t, err)
	require.True(t, empty)
}

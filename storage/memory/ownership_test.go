package memory_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
)

func TestOwnershipValidators(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()

	for _, validator := range []storage.OwnershipValidator{ks, cs, idx, sp, crl} {
		empty, err := validator.Empty()
		require.NoError(t, err)
		require.True(t, empty)
		owned, err := validator.Owned()
		require.NoError(t, err)
		require.True(t, owned)
	}

	require.NoError(t, ks.Put(&cert.Pair{Name: "client", KeyPEM: []byte("key")}))

	for _, validator := range []storage.OwnershipValidator{ks, cs, idx, sp, crl} {
		empty, err := validator.Empty()
		require.NoError(t, err)
		require.False(t, empty)
		owned, err := validator.Owned()
		require.NoError(t, err)
		require.True(t, owned)
	}

	backend := memory.NewBackend()
	pk, err := pki.New(pki.Config{NoPass: true}, backend)
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	empty, err := backend.Empty()
	require.NoError(t, err)
	require.False(t, empty)
}

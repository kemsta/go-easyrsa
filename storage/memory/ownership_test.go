package memory_test

import (
	"testing"

	"github.com/stretchr/testify/require"

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

	pk, err := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("client1")
	require.NoError(t, err)

	for _, validator := range []storage.OwnershipValidator{ks, cs, idx, sp, crl} {
		empty, err := validator.Empty()
		require.NoError(t, err)
		require.False(t, empty)
		owned, err := validator.Owned()
		require.NoError(t, err)
		require.True(t, owned)
	}
}

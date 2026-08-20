package storage_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

type fakeOwnershipValidator struct {
	empty    bool
	owned    bool
	emptyErr error
	ownedErr error
}

func (v fakeOwnershipValidator) Empty() (bool, error) { return v.empty, v.emptyErr }
func (v fakeOwnershipValidator) Owned() (bool, error) { return v.owned, v.ownedErr }

func TestValidateOwnership_AllowsEmpty(t *testing.T) {
	err := storage.ValidateOwnership(fakeOwnershipValidator{empty: true})
	require.NoError(t, err)
}

func TestValidateOwnership_AllowsOwned(t *testing.T) {
	err := storage.ValidateOwnership(fakeOwnershipValidator{owned: true})
	require.NoError(t, err)
}

func TestValidateOwnership_RejectsForeign(t *testing.T) {
	err := storage.ValidateOwnership(fakeOwnershipValidator{})
	require.ErrorIs(t, err, storage.ErrForeignStorage)
}

func TestValidateOwnership_PropagatesErrors(t *testing.T) {
	err := storage.ValidateOwnership(fakeOwnershipValidator{emptyErr: errors.New("boom")})
	require.EqualError(t, err, "boom")

	err = storage.ValidateOwnership(fakeOwnershipValidator{ownedErr: errors.New("owned-boom")})
	require.EqualError(t, err, "owned-boom")
}

func TestHexSerial_UppercaseEvenLength(t *testing.T) {
	require.Equal(t, "01", storage.HexSerial(big.NewInt(1)))
	require.Equal(t, "0A", storage.HexSerial(big.NewInt(10)))
	require.Equal(t, "0100", storage.HexSerial(big.NewInt(256)))
}

func TestValidateArtifactPath(t *testing.T) {
	t.Parallel()

	for _, valid := range []string{
		"crl.pem",
		"private/client.p12",
		"issued/nested/client.p7b",
	} {
		valid := valid
		t.Run("valid_"+valid, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, storage.ValidateArtifactPath(valid))
		})
	}

	for _, invalid := range []string{
		"",
		".",
		"..",
		"../secret",
		"private/../../secret",
		"/absolute",
		"private\\secret",
		"C:/private/client.p12",
		"private//client.p12",
		"private/./client.p12",
		"private/client.p12/..",
		"nul\x00path",
	} {
		invalid := invalid
		t.Run("invalid", func(t *testing.T) {
			t.Parallel()
			require.Error(t, storage.ValidateArtifactPath(invalid), invalid)
		})
	}
}

func TestValidateEntityNameAndSerial(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"client", "client one", "client@example.test"} {
		require.NoError(t, storage.ValidateEntityName(name))
	}
	for _, name := range []string{"", ".", "..", "../client", "client/name", "client\\name", "client..name", "nul\x00name"} {
		require.Error(t, storage.ValidateEntityName(name), name)
	}
	require.Error(t, storage.ValidateSerial(nil))
	require.Error(t, storage.ValidateSerial(big.NewInt(0)))
	require.Error(t, storage.ValidateSerial(big.NewInt(-1)))
	require.NoError(t, storage.ValidateSerial(big.NewInt(1)))
}

func TestValidateArtifactVisibility(t *testing.T) {
	t.Parallel()
	require.NoError(t, storage.ValidateArtifactVisibility(storage.ArtifactPublic))
	require.NoError(t, storage.ValidateArtifactVisibility(storage.ArtifactPrivate))
	require.Error(t, storage.ValidateArtifactVisibility(storage.ArtifactVisibility(99)))
}

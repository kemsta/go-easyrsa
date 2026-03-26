package storage_test

import (
	"errors"
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

package pki_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
)

type indexFailureBackend struct {
	storage.Backend
	err error
}

func (b *indexFailureBackend) Update(fn func(storage.Components) error) error {
	return b.Backend.Update(func(components storage.Components) error {
		return fn(indexFailureComponents{Components: components, err: b.err})
	})
}

type indexUpdateFailureBackend struct {
	storage.Backend
	err error
}

func (b *indexUpdateFailureBackend) Update(fn func(storage.Components) error) error {
	return b.Backend.Update(func(components storage.Components) error {
		return fn(indexUpdateFailureComponents{Components: components, err: b.err})
	})
}

type indexUpdateFailureComponents struct {
	storage.Components
	err error
}

func (c indexUpdateFailureComponents) Index() storage.IndexDB {
	return &errUpdateIndexDB{inner: c.Components.Index(), errOnUpdate: c.err}
}

type indexFailureComponents struct {
	storage.Components
	err error
}

func (c indexFailureComponents) Index() storage.IndexDB {
	return &errRecordIndexDB{inner: c.Components.Index(), errOnRecord: c.err}
}

func TestPKIMutationRollsBackAcrossStorageFacets(t *testing.T) {
	t.Parallel()

	backend := memory.NewBackend()
	writeErr := errors.New("index write failed")
	pk, err := pki.New(pki.Config{NoPass: true, SequentialSerial: true}, &indexFailureBackend{
		Backend: backend,
		err:     writeErr,
	})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.ErrorIs(t, err, writeErr)

	cleanPKI, err := pki.New(pki.Config{NoPass: true, SequentialSerial: true}, backend)
	require.NoError(t, err)
	_, err = cleanPKI.ShowCA()
	require.ErrorIs(t, err, storage.ErrNotFound)
	pair, err := cleanPKI.BuildCA()
	require.NoError(t, err)
	serial, err := pair.Serial()
	require.NoError(t, err)
	require.EqualValues(t, 1, serial.Int64(), "rolled-back serial advancement must not leak")
}

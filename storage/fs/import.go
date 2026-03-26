package fs

import (
	"fmt"
	"math/big"

	"github.com/kemsta/go-easyrsa/cert"
	"github.com/kemsta/go-easyrsa/storage"
)

// ReplacePairs imports a streamed pair set into the filesystem backend.
// The input stream is expected to be sorted in ascending serial order so that
// the latest pair for each name becomes the named certificate/key in the
// easy-rsa layout while all certificates remain available in certs_by_serial/.
func (ks *KeyStorage) ReplacePairs(stream storage.PairStream) error {
	return stream(func(pair *cert.Pair) error {
		return ks.Put(pair)
	})
}

// SetNext sets the next serial to be returned by Next().
func (sp *SerialProvider) SetNext(next *big.Int) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if next == nil || next.Sign() <= 0 {
		return fmt.Errorf("storage/fs: next serial must be positive")
	}
	return writeAtomic(sp.path, []byte(storage.HexSerial(next)+"\n"))
}

var (
	_ storage.PairReplacer  = (*KeyStorage)(nil)
	_ storage.IndexReplacer = (*IndexDB)(nil)
	_ storage.SerialSetter  = (*SerialProvider)(nil)
)

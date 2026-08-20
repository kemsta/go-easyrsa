package storage

import (
	"crypto/x509"
	"math/big"
	"time"

	"github.com/kemsta/go-easyrsa/v2/cert"
)

// ReadOnlyComponents wraps storage facets so mutation attempts fail with
// ErrReadOnly. It is used by backend View implementations to enforce their
// non-mutating contract.
func ReadOnlyComponents(components Components) Components {
	return &readOnlyComponents{components: components}
}

type readOnlyComponents struct{ components Components }

func (c *readOnlyComponents) Keys() KeyStorage {
	return readOnlyKeyStorage{reader: c.components.Keys()}
}
func (c *readOnlyComponents) CSRs() CSRStorage {
	return readOnlyCSRStorage{reader: c.components.CSRs()}
}
func (c *readOnlyComponents) Index() IndexDB {
	return readOnlyIndexDB{reader: c.components.Index()}
}
func (c *readOnlyComponents) Serials() SerialProvider { return readOnlySerialProvider{} }
func (c *readOnlyComponents) CRLs() CRLHolder {
	return readOnlyCRLHolder{reader: c.components.CRLs()}
}
func (c *readOnlyComponents) Artifacts() ArtifactStorage {
	return readOnlyArtifactStorage{reader: c.components.Artifacts()}
}
func (c *readOnlyComponents) Lifecycle() LifecycleStorage {
	return readOnlyLifecycleStorage{reader: c.components.Lifecycle()}
}

type readOnlyKeyStorage struct{ reader KeyStorage }

func (s readOnlyKeyStorage) Put(*cert.Pair) error          { return ErrReadOnly }
func (s readOnlyKeyStorage) DeleteByName(string) error     { return ErrReadOnly }
func (s readOnlyKeyStorage) DeleteBySerial(*big.Int) error { return ErrReadOnly }
func (s readOnlyKeyStorage) GetByName(name string) ([]*cert.Pair, error) {
	return s.reader.GetByName(name)
}
func (s readOnlyKeyStorage) GetLastByName(name string) (*cert.Pair, error) {
	return s.reader.GetLastByName(name)
}
func (s readOnlyKeyStorage) GetBySerial(serial *big.Int) (*cert.Pair, error) {
	return s.reader.GetBySerial(serial)
}
func (s readOnlyKeyStorage) GetPrivateKey(name string) ([]byte, error) {
	return s.reader.GetPrivateKey(name)
}
func (s readOnlyKeyStorage) GetAll() ([]*cert.Pair, error) { return s.reader.GetAll() }
func (s readOnlyKeyStorage) CurrentCertificates() ([]CurrentCertificate, error) {
	store, ok := s.reader.(CurrentCertificateStore)
	if !ok {
		return nil, ErrReadOnly
	}
	return store.CurrentCertificates()
}
func (s readOnlyKeyStorage) ReplaceCurrentCertificates([]CurrentCertificate) error {
	return ErrReadOnly
}
func (s readOnlyKeyStorage) ExportPairs(yield func(*cert.Pair) error) error {
	if exporter, ok := s.reader.(PairExporter); ok {
		return exporter.ExportPairs(yield)
	}
	pairs, err := s.reader.GetAll()
	if err != nil {
		return err
	}
	for _, pair := range pairs {
		if err := yield(pair); err != nil {
			return err
		}
	}
	return nil
}

type readOnlyCSRStorage struct{ reader CSRStorage }

func (s readOnlyCSRStorage) PutCSR(string, []byte) error { return ErrReadOnly }
func (s readOnlyCSRStorage) DeleteCSR(string) error      { return ErrReadOnly }
func (s readOnlyCSRStorage) GetCSR(name string) ([]byte, error) {
	return s.reader.GetCSR(name)
}
func (s readOnlyCSRStorage) ListCSRs() ([]string, error) { return s.reader.ListCSRs() }

type readOnlyIndexDB struct{ reader IndexDB }

func (db readOnlyIndexDB) Record(IndexEntry) error { return ErrReadOnly }
func (db readOnlyIndexDB) Update(*big.Int, CertStatus, time.Time, cert.RevocationReason) error {
	return ErrReadOnly
}
func (db readOnlyIndexDB) RecordAndUpdate(IndexEntry, *big.Int, CertStatus, time.Time, cert.RevocationReason) error {
	return ErrReadOnly
}
func (db readOnlyIndexDB) Query(filter IndexFilter) ([]IndexEntry, error) {
	return db.reader.Query(filter)
}

type readOnlySerialProvider struct{}

func (readOnlySerialProvider) Next() (*big.Int, error) { return nil, ErrReadOnly }

type readOnlyCRLHolder struct{ reader CRLHolder }

func (h readOnlyCRLHolder) Put([]byte) error { return ErrReadOnly }
func (h readOnlyCRLHolder) Get() (*x509.RevocationList, error) {
	return h.reader.Get()
}

type readOnlyArtifactStorage struct{ reader ArtifactStorage }

func (s readOnlyArtifactStorage) PutArtifact(Artifact) error  { return ErrReadOnly }
func (s readOnlyArtifactStorage) DeleteArtifact(string) error { return ErrReadOnly }
func (s readOnlyArtifactStorage) GetArtifact(name string) (Artifact, error) {
	return s.reader.GetArtifact(name)
}

type readOnlyLifecycleStorage struct{ reader LifecycleStorage }

func (s readOnlyLifecycleStorage) MoveIssuedToExpired(string, *big.Int) error { return ErrReadOnly }
func (s readOnlyLifecycleStorage) MoveIssuedToRenewed(string, *big.Int) error { return ErrReadOnly }
func (s readOnlyLifecycleStorage) MoveIssuedToRevoked(string, *big.Int) error {
	return ErrReadOnly
}
func (s readOnlyLifecycleStorage) MoveExpiredToRevoked(string, *big.Int) error {
	return ErrReadOnly
}
func (s readOnlyLifecycleStorage) MoveRenewedToRevoked(string, *big.Int) error {
	return ErrReadOnly
}
func (s readOnlyLifecycleStorage) GetExpiredCertificate(name string) ([]byte, error) {
	return s.reader.GetExpiredCertificate(name)
}
func (s readOnlyLifecycleStorage) GetRenewedCertificate(name string) ([]byte, error) {
	return s.reader.GetRenewedCertificate(name)
}
func (s readOnlyLifecycleStorage) ExportState() (LifecycleState, error) {
	return s.reader.ExportState()
}
func (s readOnlyLifecycleStorage) ReplaceState(LifecycleState) error { return ErrReadOnly }

var (
	_ Components              = (*readOnlyComponents)(nil)
	_ PairExporter            = readOnlyKeyStorage{}
	_ CurrentCertificateStore = readOnlyKeyStorage{}
)

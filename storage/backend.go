package storage

// Backend groups all storage facets under one consistency and transaction
// boundary. View is for read-only operations. Update commits changes only when
// its callback returns nil.
type Backend interface {
	// EnsureLayout creates missing layout elements without replacing existing
	// data. It is idempotent for writable backends.
	EnsureLayout() error
	// Initialize creates a fresh layout. An existing owned layout is replaced
	// only when reset is true.
	Initialize(reset bool) error
	ReadOnly() bool
	View(func(Components) error) error
	Update(func(Components) error) error
}

// Components exposes the independently testable storage facets available
// inside a backend view or update transaction.
type Components interface {
	Empty() (bool, error)
	Keys() KeyStorage
	CSRs() CSRStorage
	Index() IndexDB
	Serials() SerialProvider
	CRLs() CRLHolder
	Artifacts() ArtifactStorage
	Lifecycle() LifecycleStorage
}

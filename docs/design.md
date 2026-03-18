# go-easyrsa v2 Library Design

## Goals

- Full parity with easy-rsa (OpenVPN/easy-rsa3) command set
- Pluggable storage backends (filesystem, in-memory, custom)
- Filesystem storage compatible with easy-rsa's PKI directory layout
- Suitable for e2e testing against the real easy-rsa binary

---

## Package Structure

```
go-easyrsa/
├── pki/                    # Main package — all PKI operations
│   ├── pki.go              # PKI struct, constructors
│   ├── ca.go               # CA operations
│   ├── cert.go             # Certificate operations
│   ├── csr.go              # CSR operations
│   ├── revoke.go           # Revocation
│   ├── export.go           # Export (P12, P7, P8, P1)
│   ├── inspect.go          # Show/Verify
│   └── options.go          # Option type and named option funcs
├── storage/                # Storage interfaces and implementations
│   ├── storage.go          # All interfaces + sentinel errors
│   ├── fs/                 # Filesystem (compatible with easy-rsa layout)
│   │   ├── storage.go
│   │   └── index.go        # index.txt compatibility
│   └── memory/             # In-memory (for unit tests)
│       └── storage.go
├── cert/                   # Certificate and key pair types
│   ├── pair.go
│   └── csr.go
├── crypto/                 # Crypto primitives
│   ├── key.go              # GenKey (RSA/ECDSA/Ed25519)
│   └── dh.go               # DH parameters
├── cmd/easyrsa/            # CLI (updated)
├── subprojects/easy-rsa/   # Git submodule — reference implementation
└── docs/
    ├── design.md
    └── easyrsa-parity.md
```

---

## cert.Pair

`Pair` holds raw PEM bytes as the single source of truth.
All metadata is derived from the certificate on demand — no duplicated fields,
no consistency risk between stored fields and actual certificate contents.

```go
// Pair holds a certificate and optionally its private key.
// KeyPEM may be nil in cert-only scenarios (e.g. after signing an external CSR).
type Pair struct {
    Name    string // storage key — the entity name, may differ from CN in org mode
    KeyPEM  []byte // nil if key is not held locally
    CertPEM []byte
}

// Certificate parses and returns the x509.Certificate from CertPEM.
func (p *Pair) Certificate() (*x509.Certificate, error)

// PrivateKey parses KeyPEM using PKCS8, supporting RSA, ECDSA, and Ed25519.
// Returns an error if KeyPEM is nil.
func (p *Pair) PrivateKey() (crypto.PrivateKey, error)

// Serial returns the certificate serial number.
func (p *Pair) Serial() (*big.Int, error)

// CertType derives the certificate type from extensions:
//   BasicConstraints.IsCA                           → CertTypeCA
//   ExtKeyUsageServerAuth only                      → CertTypeServer
//   ExtKeyUsageClientAuth only                      → CertTypeClient
//   ExtKeyUsageServerAuth + ExtKeyUsageClientAuth   → CertTypeServerClient
func (p *Pair) CertType() (CertType, error)

// IsCA returns true if the certificate has the CA basic constraint.
func (p *Pair) IsCA() (bool, error)

// HasKey reports whether a private key is stored locally.
func (p *Pair) HasKey() bool
```

### CertType

```go
type CertType string

const (
    CertTypeCA           CertType = "ca"
    CertTypeServer       CertType = "server"
    CertTypeClient       CertType = "client"
    CertTypeServerClient CertType = "serverClient"
)
```

### Revocation reasons (RFC 5280)

```go
type RevocationReason int

const (
    ReasonUnspecified          RevocationReason = 0
    ReasonKeyCompromise        RevocationReason = 1
    ReasonCACompromise         RevocationReason = 2
    ReasonAffiliationChanged   RevocationReason = 3
    ReasonSuperseded           RevocationReason = 4
    ReasonCessationOfOperation RevocationReason = 5
)
```

---

## Storage Interfaces (`storage/storage.go`)

### Sentinel errors

```go
var (
    ErrNotFound = errors.New("not found")
    ErrConflict = errors.New("already exists")
)
```

Callers distinguish "not found" from I/O errors via `errors.Is(err, storage.ErrNotFound)`.

### KeyStorage

```go
// KeyStorage stores key+certificate pairs.
// The Name field on Pair is the storage key (entity name).
type KeyStorage interface {
    Put(pair *cert.Pair) error
    GetByName(name string) ([]*cert.Pair, error)   // returns ErrNotFound if none
    GetLastByName(name string) (*cert.Pair, error) // highest serial; ErrNotFound if none
    GetBySerial(serial *big.Int) (*cert.Pair, error)
    DeleteByName(name string) error
    DeleteBySerial(serial *big.Int) error
    GetAll() ([]*cert.Pair, error)
}
```

### CSRStorage

```go
// CSRStorage stores Certificate Signing Requests (PEM-encoded).
type CSRStorage interface {
    PutCSR(name string, csrPEM []byte) error
    GetCSR(name string) ([]byte, error) // ErrNotFound if absent
    DeleteCSR(name string) error
    ListCSRs() ([]string, error)
}
```

### IndexDB

```go
// IndexDB is the certificate database, analogous to easy-rsa's index.txt.
// It tracks all issued certificates and their current status.
type IndexDB interface {
    Record(entry IndexEntry) error
    Update(serial *big.Int, status CertStatus) error
    Query(filter IndexFilter) ([]IndexEntry, error)
}

type CertStatus string

const (
    StatusValid   CertStatus = "V"
    StatusRevoked CertStatus = "R"
    StatusExpired CertStatus = "E"
)

type IndexEntry struct {
    Status         CertStatus
    ExpiresAt      time.Time
    RevokedAt      time.Time // zero if not revoked
    Serial         *big.Int
    Subject        pkix.Name
    RevocationReason RevocationReason
}

type IndexFilter struct {
    Status *CertStatus  // nil = all statuses
    Name   string       // empty = all names
}
```

### SerialProvider

```go
// SerialProvider generates monotonically increasing serial numbers.
type SerialProvider interface {
    Next() (*big.Int, error)
}
```

### CRLHolder

```go
// CRLHolder stores and retrieves the Certificate Revocation List.
type CRLHolder interface {
    Put(pemBytes []byte) error
    Get() (*x509.RevocationList, error) // returns empty list (not error) if none exists
}
```

---

## PKI Configuration

```go
type Config struct {
    // Crypto defaults — overridable per-operation via Option
    KeyAlgo    KeyAlgo        // rsa | ecdsa | ed25519 (default: rsa)
    KeySize    int            // RSA only: 2048/3072/4096 (default: 2048)
    Curve      elliptic.Curve // ECDSA only: P-256, P-384, P-521 (default: P-256)
    DigestAlgo crypto.Hash    // SHA-256, SHA-384, SHA-512 (default: SHA-256)

    // Certificate validity defaults
    DefaultDays    int // end-entity cert validity (default: 825)
    CADays         int // CA cert validity (default: 3650)
    CRLDays        int // CRL validity (default: 180)
    PreExpiryDays  int // warn window for ShowExpiring (default: 90)

    // Subject defaults
    SubjTemplate pkix.Name
    DNMode       DNMode // cn_only | org (default: cn_only)

    // Serial number generation
    RandomSerial bool // true = random 128-bit serial; false = incremental (default: true)

    // Key protection defaults
    // The library stores key PEM bytes as returned by generation.
    // NoPass=true → keys are stored unencrypted (PKCS8 plaintext).
    // NoPass=false → per-operation WithPassphrase() must supply the passphrase,
    //                otherwise generation fails rather than silently storing plaintext.
    NoPass bool // default: false (require explicit WithPassphrase or WithNoPass per-op)

    // CA key passphrase — used when decrypting the CA private key for signing.
    // Equivalent to EASYRSA_PASSIN for the CA key.
    // If empty and the CA key is encrypted, signing operations return an error.
    CAPassphrase string

    // Netscape extensions (deprecated, for compatibility)
    NetscapeExtensions bool   // default: false
    NetscapeComment    string // default: "Easy-RSA Generated Certificate"

    // CA name in storage
    CAName string // default: "ca"
}

type KeyAlgo string

const (
    AlgoRSA     KeyAlgo = "rsa"
    AlgoECDSA   KeyAlgo = "ecdsa"
    AlgoEd25519 KeyAlgo = "ed25519"
)

type DNMode string

const (
    DNModeCNOnly DNMode = "cn_only"
    DNModeOrg    DNMode = "org"
)
```

---

## PKI Struct

```go
// PKI orchestrates all certificate operations.
// All storage dependencies are private — callers interact only through PKI methods.
type PKI struct {
    storage    storage.KeyStorage
    csrStorage storage.CSRStorage
    index      storage.IndexDB
    serial     storage.SerialProvider
    crlHolder  storage.CRLHolder
    config     Config
}

// New constructs a PKI with explicit storage dependencies.
func New(
    cfg Config,
    s storage.KeyStorage,
    csr storage.CSRStorage,
    idx storage.IndexDB,
    sp storage.SerialProvider,
    crl storage.CRLHolder,
) *PKI

// NewWithFS constructs a PKI backed by a filesystem PKI directory
// using the easy-rsa-compatible layout.
func NewWithFS(pkiDir string, cfg Config) (*PKI, error)
```

Storage fields are always private. There is no public `Storage` field — bypassing
PKI logic (serial assignment, index recording, CRL management) via direct storage
access is not possible.

---

## Option — Semi-Open Interface

Operations accept `...Option` for both key generation and certificate properties.
The `Option` type operates on an internal `options` struct (not directly on
`*x509.Certificate`), so the interface is closed for common cases and open
for advanced ones via an explicit escape hatch.

```go
// Option configures a key+certificate generation operation.
type Option func(*options)

type options struct {
    // Key generation
    keyAlgo KeyAlgo
    keySize int
    curve   elliptic.Curve

    // Key protection (per-operation overrides of Config defaults)
    noPass     *bool  // nil = use Config.NoPass
    passphrase string // encrypts the generated private key (PKCS8 encrypted PEM)

    // Certificate validity
    notBefore time.Time
    notAfter  time.Time

    // Subject override (merged with PKI config default)
    subject       *pkix.Name
    subjectSerial string // certificate Subject serialNumber field (distinct from x509 serial)

    // Subject Alternative Names
    dnsNames    []string
    ipAddresses []net.IP
    emailAddrs  []string

    // SAN behaviour
    autoSAN     bool // derive SAN from CN (DNS or IP based on format)
    sanCritical bool

    // Extension criticality overrides
    bcCritical  bool // basicConstraints
    kuCritical  bool // keyUsage
    ekuCritical bool // extendedKeyUsage

    // CSR signing behaviour (used by SignReq)
    copyCSRExtensions bool     // copy extensions from CSR (e.g. SANs)
    subjectOverride   *pkix.Name // replace subject DN when signing
    preserveDN        bool     // preserve CSR DN field order instead of CA order

    // Sub-CA path length constraint (used by BuildCA for intermediate CAs)
    subCAPathLen *int // nil = no constraint; 0 = no further intermediates

    // PKCS#12 export
    p12FriendlyName string

    // Escape hatch: applied last, after all named options
    certModifiers []func(*x509.Certificate)
}
```

### Named options

```go
// Key generation
func WithKeyAlgo(algo KeyAlgo) Option
func WithKeySize(bits int) Option       // RSA only
func WithCurve(c elliptic.Curve) Option // ECDSA only

// Key protection
func WithPassphrase(passphrase string) Option // encrypt generated key with passphrase
func WithNoPass() Option                      // store key unencrypted, regardless of Config.NoPass

// Validity
func WithNotBefore(t time.Time) Option
func WithNotAfter(t time.Time) Option
func WithDays(days int) Option // shorthand: NotAfter = now + days

// Subject
func WithCN(cn string) Option
func WithSubject(name pkix.Name) Option
func WithSubjectSerial(serial string) Option // Subject serialNumber field

// SANs
func WithAutoSAN() Option                        // derive SAN from CN automatically
func WithDNSNames(names ...string) Option
func WithIPAddresses(ips ...net.IP) Option
func WithEmailAddresses(addrs ...string) Option
func WithSANCritical() Option                    // mark SAN extension as critical

// Extension criticality
func WithBasicConstraintsCritical() Option
func WithKeyUsageCritical() Option
func WithExtKeyUsageCritical() Option

// CSR signing
func WithCopyCSRExtensions() Option              // copy extensions from CSR (incl. SANs)
func WithSubjectOverride(name pkix.Name) Option  // replace subject when signing CSR
func WithPreserveDN() Option                     // keep CSR DN field order

// Sub-CA
func WithSubCAPathLen(n int) Option // path length constraint; 0 = no further intermediates

// Export
func WithP12FriendlyName(name string) Option
```

### Escape hatch (semi-open)

```go
// WithCertModifier provides direct access to the x509.Certificate template
// for advanced cases not covered by named options.
// Applied after all named options; multiple modifiers run in order.
func WithCertModifier(fn func(*x509.Certificate)) Option
```

The PKI methods apply options in a defined order: key options first (key
generation), then named cert options, then modifiers. This prevents named
options from being silently overridden by earlier modifier calls.

---

## PKI Methods

### CA operations

```go
func (p *PKI) BuildCA(opts ...Option) (*cert.Pair, error)
func (p *PKI) RenewCA(opts ...Option) (*cert.Pair, error)
func (p *PKI) ShowCA() (*cert.Pair, error)
```

### CSR operations

```go
func (p *PKI) GenReq(name string, opts ...Option) (csrPEM []byte, err error)
func (p *PKI) ImportReq(name string, csrPEM []byte) error
func (p *PKI) SignReq(name string, certType cert.CertType, opts ...Option) (*cert.Pair, error)
```

### Certificate operations

```go
func (p *PKI) BuildClientFull(name string, opts ...Option) (*cert.Pair, error)
func (p *PKI) BuildServerFull(name string, opts ...Option) (*cert.Pair, error)
func (p *PKI) BuildServerClientFull(name string, opts ...Option) (*cert.Pair, error)
func (p *PKI) Renew(name string, opts ...Option) (*cert.Pair, error)
```

### Revocation

Revocation is batched: all serials are collected, the CRL is read once,
updated, and written once — regardless of how many certs are revoked.

```go
func (p *PKI) Revoke(name string, reason cert.RevocationReason) error
func (p *PKI) RevokeBySerial(serial *big.Int, reason cert.RevocationReason) error
func (p *PKI) RevokeExpired(name string, reason cert.RevocationReason) error
func (p *PKI) GenCRL() ([]byte, error)

// IsRevoked returns (false, err) if the CRL cannot be read.
// Callers must handle the error — a missing/corrupt CRL is not treated as "all valid".
func (p *PKI) IsRevoked(serial *big.Int) (bool, error)
```

### Inspect

```go
func (p *PKI) ShowCert(name string) (*cert.Pair, error)
func (p *PKI) ShowCRL() (*x509.RevocationList, error)
func (p *PKI) ShowExpiring(withinDays int) ([]*cert.Pair, error)
func (p *PKI) ShowRevoked() ([]*cert.Pair, error)
func (p *PKI) VerifyCert(name string) error
func (p *PKI) ExpireCert(name string) error
func (p *PKI) UpdateDB() error
```

### Export

```go
func (p *PKI) ExportP12(name string, password string) ([]byte, error)
func (p *PKI) ExportP7(name string) ([]byte, error)
func (p *PKI) ExportP8(name string, password string) ([]byte, error)
func (p *PKI) ExportP1(name string) ([]byte, error)
```

### Other

```go
func (p *PKI) GenDH(bits int) ([]byte, error)
func (p *PKI) SetPass(name string, oldPass, newPass string) error
```

---

## Filesystem Storage Layout

Compatible with easy-rsa, enabling interoperability with the real binary in e2e tests.

```
pki/
├── ca.crt                  # CA certificate
├── private/
│   ├── ca.key              # CA private key
│   ├── server.key
│   └── client.key
├── issued/                 # Signed certificates
│   ├── server.crt
│   └── client.crt
├── reqs/                   # Certificate signing requests
│   └── server.req
├── certs_by_serial/        # Certificates indexed by serial number (hex filename)
│   └── 01.pem
├── index.txt               # OpenSSL-style certificate database
├── serial                  # Current serial number (hex string)
└── crl.pem                 # Certificate Revocation List
```

### index.txt format

```
<status>\t<expiry>\t<revocation_date>\t<serial>\tunknown\t<subject_DN>
```

- Status: `V` (valid), `R` (revoked), `E` (expired)
- Dates: `YYMMDDHHMMSSZ` format
- Revocation date: empty for valid certs

---

## Known Issues Fixed vs v1

| Issue | v1 | v2 |
|-------|----|----|
| `PKI.Storage` public field | yes | removed — all private |
| `IsRevoked` swallows CRL error → returns false | yes | returns `(bool, error)` |
| `RevokeAll` does N CRL reads+writes | yes | single read + write |
| `DeleteByCN` uses `os.Remove` on directory | yes | `os.RemoveAll` |
| Storage "not found" indistinguishable from I/O error | yes | `ErrNotFound` sentinel |
| Silent file read errors in `GetAll` / `GetBySerial` | yes | propagated |
| `GetLastCA` hardcoded to CN "ca" | yes | `Config.CAName` |
| `Option` operates directly on `*x509.Certificate` | yes | internal `options` struct + escape hatch |
| Key algo hardcoded to RSA 2048 | yes | `Config` + `WithKeyAlgo` / `WithKeySize` |
| `Pair.CN` and `Pair.Serial` duplicated from cert | yes | derived via methods |
| PKCS1-only key parsing (RSA only) | yes | PKCS8 (`crypto.PrivateKey`) |
| Inconsistent casing: `GetByCN` vs `DeleteByCn` | yes | consistent `ByName` / `BySerial` |

---

## easy-rsa Environment Variable Coverage

All easy-rsa env vars are grouped below. The library never reads env vars directly —
equivalents are passed via `Config` (PKI-wide) or `Option` (per-operation).

### Covered — Config field

| easy-rsa env var | Config field | Notes |
|---|---|---|
| `EASYRSA_PKI` | `NewWithFS(pkiDir, cfg)` | pkiDir parameter |
| `EASYRSA_ALGO` | `Config.KeyAlgo` | rsa / ecdsa / ed25519 |
| `EASYRSA_KEY_SIZE` | `Config.KeySize` | RSA only |
| `EASYRSA_CURVE` | `Config.Curve` | ECDSA only |
| `EASYRSA_DIGEST` | `Config.DigestAlgo` | |
| `EASYRSA_CA_EXPIRE` | `Config.CADays` | |
| `EASYRSA_CERT_EXPIRE` | `Config.DefaultDays` | |
| `EASYRSA_CRL_DAYS` | `Config.CRLDays` | |
| `EASYRSA_PRE_EXPIRY_WINDOW` | `Config.PreExpiryDays` | default for ShowExpiring |
| `EASYRSA_DN` | `Config.DNMode` | cn_only / org |
| `EASYRSA_REQ_COUNTRY/PROVINCE/CITY/ORG/OU/EMAIL` | `Config.SubjTemplate` | pkix.Name fields |
| `EASYRSA_RAND_SN` | `Config.RandomSerial` | |
| `EASYRSA_NO_PASS` | `Config.NoPass` | global default |
| `EASYRSA_PASSIN` (CA key) | `Config.CAPassphrase` | used to decrypt CA key for signing |
| `EASYRSA_NS_SUPPORT` | `Config.NetscapeExtensions` | deprecated |
| `EASYRSA_NS_COMMENT` | `Config.NetscapeComment` | deprecated |

### Covered — Option func

| easy-rsa env var | Option func | Notes |
|---|---|---|
| `EASYRSA_REQ_CN` | `WithCN()` | |
| `EASYRSA_REQ_SERIAL` | `WithSubjectSerial()` | Subject field, not x509 serial |
| `EASYRSA_ALIAS_DAYS` | `WithDays()` | per-op validity override |
| `EASYRSA_START_DATE` | `WithNotBefore()` | |
| `EASYRSA_END_DATE` | `WithNotAfter()` | |
| `EASYRSA_SAN` | `WithDNSNames()` / `WithIPAddresses()` / `WithEmailAddresses()` | |
| `EASYRSA_AUTO_SAN` | `WithAutoSAN()` | derive SAN from CN |
| `EASYRSA_SAN_CRIT` | `WithSANCritical()` | |
| `EASYRSA_BC_CRIT` | `WithBasicConstraintsCritical()` | |
| `EASYRSA_KU_CRIT` | `WithKeyUsageCritical()` | |
| `EASYRSA_EKU_CRIT` | `WithExtKeyUsageCritical()` | |
| `EASYRSA_EXTRA_EXTS` | `WithCertModifier()` | escape hatch |
| `EASYRSA_CP_EXT` | `WithCopyCSRExtensions()` | used in SignReq |
| `EASYRSA_NEW_SUBJECT` | `WithSubjectOverride()` | used in SignReq |
| `EASYRSA_PRESERVE_DN` | `WithPreserveDN()` | used in SignReq, org mode |
| `EASYRSA_SUBCA_LEN` | `WithSubCAPathLen()` | intermediate CA path length |
| `EASYRSA_PASSOUT` | `WithPassphrase()` | encrypt generated key |
| `EASYRSA_NO_PASS` (per-op) | `WithNoPass()` | per-op override of Config.NoPass |
| `EASYRSA_P12_FR_NAME` | `WithP12FriendlyName()` | ExportP12 |

### Not applicable — shell/binary-specific

These env vars control easy-rsa's shell execution environment.
A Go library has no equivalent concept.

| easy-rsa env var | Reason not applicable |
|---|---|
| `EASYRSA` | path to shell script installation |
| `EASYRSA_OPENSSL` | path to openssl binary (library uses crypto/x509 directly) |
| `EASYRSA_TEMP_DIR` | temp files for shell subprocess operations |
| `EASYRSA_SSL_CONF` | openssl config file (not used) |
| `EASYRSA_EXT_DIR` | x509-types directory for openssl (not used) |
| `EASYRSA_VARS_FILE` | shell vars file loading |
| `EASYRSA_OPENVPN` | path to openvpn binary |
| `EASYRSA_BATCH` | suppress interactive prompts (library has none) |
| `EASYRSA_SILENT` | suppress shell output |
| `EASYRSA_VERBOSE` | shell debug output |
| `EASYRSA_SILENT_SSL` | silence openssl subprocess output |
| `EASYRSA_DEBUG` | shell debug mode |
| `EASYRSA_TEXT_ON/OFF` | openssl -text flag in output files |
| `EASYRSA_UMASK` | file permission mask (fs storage implementation detail) |
| `EASYRSA_NO_UMASK` | disable umask |
| `EASYRSA_KEEP_TEMP` | keep shell temp session |
| `EASYRSA_MAX_TEMP` | temp dir count limit |
| `EASYRSA_NO_INLINE` | openssl inline file creation |
| `EASYRSA_RAW_CA` | raw terminal input for CA passphrase |
| `EASYRSA_FORCE_SAFE_SSL` | regenerate openssl safe config |
| `EASYRSA_FORCE_VARS` | ignore errors in shell vars file |
| `EASYRSA_NO_LOCKFILE` | disable flock (fs storage can expose this as a storage option) |
| `EASYRSA_CALLER` | internal shell sourcing guard |
| `EASYRSA_NO_VARS` | internal shell flag |
| `EASYRSA_KDC_REALM` | Kerberos placeholder (non-functional in easy-rsa itself) |

---

## e2e Testing Strategy

The `subprojects/easy-rsa/` submodule provides the real easy-rsa binary for
integration testing:

1. Run `subprojects/easy-rsa/easyrsa3/easyrsa init-pki` to create a PKI directory
2. Use `NewWithFS(pkiDir, cfg)` to open it with go-easyrsa's filesystem storage
3. Perform operations via both tools and verify compatible output

This validates that the filesystem storage correctly reads and writes the
easy-rsa PKI layout.

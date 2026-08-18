# go-easyrsa utility-command parity design

## Status

Approved for implementation.

## Background

`go-easyrsa` v1.0.0 has positive-compatibility coverage for 28 Easy-RSA v3.2.6 commands. Six of the 16 deferred commands form a low-risk inspection and utility series:

- `show-req`
- `show-eku`
- `serial`
- `check-serial`
- `display-dn`
- `rand`

`show-renew` was initially considered for this series, but it depends on renewal archives under `renewed/issued` and `renewed/certs_by_serial`. It moves to the lifecycle series with `revoke-renewed` so this PR remains read-only.

This work retains the established compatibility contract: every upstream-valid invocation in scope must succeed in `go-easyrsa`; exact OpenSSL prose and identical rejection behavior are not required. E2E scenarios pass canonical upstream syntax to both implementations and compare stable semantics.

## Scope

### In scope

- Register and implement the six command names above.
- Add Easy-RSA-shaped library operations for CSR inspection, EKU classification, and serial lookup.
- Add a non-initializing filesystem open path for read-only PKI operations.
- Support both PKI names and explicit certificate paths for `show-eku`.
- Support certificate and CSR files for `display-dn`.
- Generate random hex with Go's cryptographic random source.
- Add ordinary tests, cross-implementation E2E, mixed-producer checks, and compatibility documentation.
- Raise the verified CLI count from 28 to 34 and reduce the deferred list from 16 to 10.

### Out of scope

- `show-renew`, renewal archive creation, and `revoke-renewed`.
- Self-signed certificate commands.
- Inline files, imported CA/TLS material, TLS key generation, and legacy `write` output.
- Exact OpenSSL text dumps, prompts, warning wording, or failure parity.
- A release or new tags. The four command-series PRs will be released together after all 16 deferred commands are complete.

## Public library API

The public API should follow Easy-RSA command semantics rather than expose lower-level implementation terminology.

### `PKI.ShowReq`

```go
func (p *PKI) ShowReq(name string) (*cert.CSR, error)
```

The method validates the storage name, loads the request through `CSRStorage`, and parses it before returning it. Like Easy-RSA's `openssl req -noout -text` path, inspection does not verify the CSR signature; a structurally valid request with a damaged signature remains inspectable. Malformed PEM or ASN.1 is an error. The returned `cert.CSR` owns a copy of the stored PEM and preserves the entity name, so callers cannot mutate storage through the returned slice.

### `PKI.ShowEKU`

```go
func (p *PKI) ShowEKU(name string) (cert.EKUType, error)
```

The method loads the current named certificate and classifies its Extended Key Usage using Easy-RSA labels. The `cert` package owns the shared classifier so the CLI path form uses exactly the same rules:

```go
type EKUType string

const (
    EKUClient       EKUType = "client"
    EKUServer       EKUType = "server"
    EKUServerClient EKUType = "serverClient"
    EKUCodeSigning  EKUType = "codeSigning"
    EKUUndefined    EKUType = "undefined"
    EKUUnknown      EKUType = "unknown"
)

func ClassifyEKU(certificate *x509.Certificate) (EKUType, error)
```

Known combinations match Easy-RSA v3.2.6. The package exports an `ErrUnknownEKU` sentinel. An empty EKU returns `EKUUndefined` together with `ErrUnknownEKU`; unsupported or mixed combinations return an `unknown` label and a wrapped `ErrUnknownEKU` that includes their numeric OIDs. This lets the CLI print Easy-RSA's classification before exiting non-zero. Future self-sign work may extend this type with Easy-RSA's `self-signed-*` labels without changing this series.

### `PKI.CheckSerial`

```go
func (p *PKI) CheckSerial(serial *big.Int) (*storage.IndexEntry, error)
```

The method checks all index states. A matching serial returns a deep copy of its entry; an available serial returns `nil, nil`. The copy owns its `big.Int`, every subject slice, and any mutable attribute value, so callers cannot mutate the underlying index. Nil or negative input is rejected. If a corrupt index contains the serial more than once, the method returns an error rather than choosing one entry.

The method name intentionally follows the Easy-RSA command. The CLI names `serial` and `check-serial` are aliases over this operation.

### Non-initializing filesystem open

```go
func OpenWithFS(pkiDir string, cfg Config) (*PKI, error)
```

`OpenWithFS` constructs and validates the filesystem-backed storage adapters without creating directories or files. `NewWithFS` reuses the same construction path and then initializes directories, preserving its current behavior. A new CLI `openPKIReadOnly` helper uses `OpenWithFS`; all existing and new inspection/verification commands migrate to it so the read-only classification is true at the filesystem boundary.

## CLI behavior

### `show-req <name> [full]`

The command calls `PKI.ShowReq` and prints stable CSR semantics: entity name, complete subject, DNS/IP/email SANs, public-key algorithm and size or curve, and signature algorithm. The `full` token is accepted for upstream syntax compatibility; it may add detail but cannot remove any stable field used by the comparator.

The command does not print raw private material or invoke OpenSSL.

### `show-eku <name-or-path>`

The command follows Easy-RSA's `test -f` behavior. A regular file, or a symlink resolving to one, is opened once and parsed. Missing and non-regular paths fall back to treating the argument as a PKI entity name and calling `PKI.ShowEKU`; this preserves successful name lookup even when a same-named directory, FIFO, or device exists. A regular file that contains malformed certificate data is an error and does not fall back.

The implementation checks non-regular entries without opening them and uses a non-blocking descriptor open where the platform supports it before the final regular-file check. This prevents FIFO blocking and closes the replacement race between path classification and parsing.

The command always prints the resulting Easy-RSA label. Known types succeed. `undefined` and unknown combinations then return a non-zero status, matching upstream semantics. Symlinks are accepted when their opened target is a regular file.

### `serial <hex> [batch]` and `check-serial <hex> [batch]`

Both names execute identical code. Hex parsing is case-insensitive, so uppercase input is accepted as an intentional extension over upstream's lowercase-only parser.

- Available serial, batch mode: success with no output.
- Occupied serial, batch mode: non-zero status with no status report.
- Non-batch mode: print either `available` or the matching index status and return success.

Batch mode is enabled by the positional `batch` token, `--batch`, or `EASYRSA_BATCH`. Parsing never allocates a serial or changes the serial counter.

### `display-dn <x509|req> <path>`

The command opens one explicit file and prints every subject attribute in deterministic multiline form. It decodes `RawSubject` as a `pkix.RDNSequence`, preserving source order, repeated attributes, multi-valued RDNs, and attributes not represented by the convenience fields on `pkix.Name`. Known OIDs use stable long names; unknown attributes use their numeric OID. Tests include common name, organization, organizational unit, country, province, locality, email, subject serial, street, postal code, repeated attributes, and an unknown OID. Only `x509` and `req` are accepted formats.

The parser uses Go's ASN.1 and `crypto/x509` packages; it does not pass user input to a subprocess.

### `rand <bytes>`

The argument is a positive base-10 byte count without a sign and must fit in a signed 64-bit count. The command streams `crypto/rand.Reader` through a hex encoder to stdout and appends one newline. It writes exactly twice the requested byte count in lowercase hex and propagates random-source and output errors.

## Read-only and security rules

All six commands are classified as read-only and bypass the PKI mutation lock. Storage-backed commands use `OpenWithFS`, not the initializing `NewWithFS`. Existing inspection and verification commands migrate to the same read-only helper.

Tests take a raw recursive filesystem snapshot before and after each storage-backed command. The snapshot records directories, regular-file bytes and modes, symlink targets, and the `serial` file; it does not call a PKI constructor or semantic state loader. Equality proves that command setup and execution create or rewrite nothing.

Explicit-path commands classify non-regular entries without opening them, then open candidate regular files once and inspect the descriptor before parsing. A symlink to a regular file remains compatible with upstream.

Inputs are parsed before PKI access where possible. Serial checks do not call `SerialProvider.Next`. Random output comes only from `crypto/rand`; tests do not substitute a predictable source in production paths.

## E2E design

The tagged CLI E2E suite remains authoritative and keeps these invariants:

- identical canonical command arguments for both implementations;
- sanitized Easy-RSA environment;
- separate stdout, stderr, status, and artifact handling;
- semantic comparison without allowlists, skips, or expected failures.

Scenarios cover:

1. `show-req` on requests made by both implementations, including full DN and SANs.
2. `show-eku` for client, server, and server-client certificates, by entity name and by an explicit certificate produced by the opposite implementation, plus a same-named directory collision that must fall back to PKI lookup.
3. Both serial aliases with an available lowercase serial in batch mode.
4. Occupied-serial reporting against a shared PKI produced in each direction.
5. `display-dn` for CSR and X.509 files produced by each implementation.
6. `rand` output shape: successful status, exact length, lowercase hex, and independent values.
7. Raw recursive filesystem equality, including the serial counter, before and after every storage-backed read-only command.

OpenSSL prose, random bytes, temporary paths, and formatting whitespace are not compared literally. Subject fields, SANs, EKU labels, serial occupancy/status, and random output shape are content-bearing and cannot be normalized away.

## Ordinary tests

Library tests cover:

- valid and malformed CSRs, acceptance of a structurally valid CSR with a damaged signature, and returned-PEM mutation isolation;
- every supported EKU class plus undefined and unknown combinations;
- serial lookup across valid, expired, and revoked entries;
- nil, negative, absent, duplicate, and malformed serial/index cases;
- mutation attempts against a returned serial entry followed by a second lookup proving deep-copy isolation;
- non-initializing filesystem open behavior for missing, incomplete, and valid PKIs;
- memory and filesystem-backed behavior where applicable.

CLI tests cover:

- canonical and extended serial syntax;
- all three batch controls;
- path-first EKU resolution, empty-EKU failure, and name lookup despite same-named non-regular entries;
- complete raw-RDN output for certificates and CSRs, including repeated and unknown attributes;
- regular files, symlinks, directories, FIFOs, malformed PEM, and replacement-race resistance;
- positive and invalid random lengths, exact output length, lowercase hex, and write failures;
- command registration and read-only lock classification.

All four modules continue to pass tests and vet on Go 1.25.13 and 1.26.6. Root and CLI E2E pass on both toolchains. `govulncheck`, `golangci-lint`, and `actionlint` remain green.

## Documentation

`docs/go-easyrsa-cli-parity.md` moves the six commands into the verified table, leaves `show-renew` in the lifecycle group, and reports 34 verified and 10 deferred command names. README claims remain bounded to the verified subset.

## Nested-module dependency flow

`cmd/go-easyrsa/go.mod` currently requires the released root module `v2.2.0` and intentionally has no local `replace`. The new CLI commands need APIs introduced by this PR, so the library commit must be pushed before CLI implementation. The branch then resolves that exact root commit to a valid `v2.2.1-0...` pseudo-version and updates only `cmd/go-easyrsa` to require it. The development-only `replace => ../..` must not return.

This keeps the nested module installable from every merged commit while avoiding an intermediate root release. If a later correction changes root library code, the CLI requirement is advanced to the correction's pseudo-version. After all four command-series PRs, the single release-preparation change replaces the pseudo-version with the final stable root release before tagging the CLI.

## Commit structure

1. Design document.
2. Library API and focused storage/certificate tests; push this commit.
3. Resolve and record the library commit's pseudo-version in `cmd/go-easyrsa`.
4. CLI commands and ordinary tests.
5. Cross-implementation E2E and compatibility documentation.

## Acceptance criteria

- All six command names are registered.
- Every command has at least one successful canonical Easy-RSA v3.2.6 E2E scenario.
- Library APIs use the Easy-RSA-shaped names and semantics described above.
- `cmd/go-easyrsa` consumes the pushed library commit by pseudo-version and contains no local `replace`.
- Explicit-path parsing never invokes OpenSSL, cannot block on a FIFO, and preserves Easy-RSA's non-regular-path fallback for `show-eku`.
- Read-only PKI construction creates no directories or files.
- `CheckSerial` returns a deep copy and never exposes mutable index state.
- Serial checks never mutate the index or serial counter.
- Random output uses `crypto/rand`, has the requested length, and is valid lowercase hex.
- Read-only commands leave both implementations' PKI state unchanged.
- The verified command matrix reaches 34 with no skips or allowlists.
- CI passes on exact Go 1.25.13 and 1.26.6 toolchains.

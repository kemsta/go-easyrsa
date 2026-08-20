# PKI methods for Easy-RSA commands

## Status

Approved for implementation. Implementation has not started.

## Background

The project exposes a Go library and a Cobra CLI. The library is the product; `cmd/go-easyrsa` is a helper for users who want Easy-RSA-compatible command syntax.

The current 34-command CLI surface passes positive-compatibility E2E against Easy-RSA v3.2.6, but several commands still contain substantive behavior in the CLI package:

- `init-pki` calls a constructor instead of a command-equivalent method;
- `expire`, `revoke`, `revoke-issued`, and `revoke-expired` own filesystem lifecycle transactions;
- export commands implement PKCS#1, PKCS#7, and PKCS#12 variants and write artifacts;
- `gen-crl` and `gen-dh` write artifacts;
- path-first `show-eku`, `display-dn`, and `rand` are implemented in the CLI;
- mutation locking, safe file staging, rollback, and artifact replacement live under `cmd/go-easyrsa`.

This split means a direct library caller cannot reproduce every supported Easy-RSA operation. It also gives direct callers weaker lifecycle safety than CLI callers.

## Architectural invariant

Every supported Easy-RSA operation is represented by a public method on `*pki.PKI`. The CLI may:

- parse argv, flags, and environment variables;
- convert textual values into typed `pki` and `cert` inputs;
- acquire external input bytes where the command has an unambiguous file argument, such as `import-req`;
- format typed results;
- map returned errors to output and exit status.

The CLI must not own certificate lifecycle rules, cryptographic encoding or parsing, artifact persistence, PKI mutation locking, or rollback.

There is no duplicate public command-service type and no `pki.CommandAPI` interface. The exported methods of `*PKI` are the API. True Easy-RSA aliases may share an internal implementation, but their command-to-method mapping remains explicit.

## Goals

- Give every one of the 34 registered commands a public `PKI` method mapping.
- Move all substantive command behavior from `cmd/go-easyrsa` into the root library.
- Give direct library callers the same safe filesystem lifecycle behavior as the CLI.
- Introduce a cohesive backend transaction boundary across keys, CSRs, index state, serial state, CRLs, lifecycle archives, and named artifacts.
- Implement the full writable contract in the filesystem and memory backends.
- Keep the legacy backend read-only with explicit `storage.ErrReadOnly` failures.
- Preserve Easy-RSA v3.2.6 positive compatibility and all existing cross-producer scenarios.
- Prepare renewal archives for the later `show-renew` and `revoke-renewed` command series.

## Non-goals

- Adding any of the 10 deferred commands.
- Implementing `show-renew` or `revoke-renewed` in this PR.
- Implementing self-signed certificates, inline files, imported CA/TLS material, TLS key generation, or legacy `write` output.
- Expanding support for controls already documented as unsupported.
- Matching OpenSSL prose, prompts, or rejection wording.
- Publishing a release or moving an existing tag.
- Creating a second command façade alongside `PKI`.

## Versioning decision

The module remains `github.com/kemsta/go-easyrsa/v2`. Clean public and storage boundaries take priority over source compatibility in this refactor. Existing methods and convenience constructors remain when they do not compromise the model, but constructor and storage API changes are allowed.

No published tag is changed by this PR. Release versioning is a separate decision after all deferred commands are complete.

## Public PKI method map

| Easy-RSA command | Public method after this refactor | Design note |
| --- | --- | --- |
| `init-pki` | `PKI.InitPKI(options)` | New explicit method; `NewWithFS` remains a non-destructive convenience wrapper. |
| `build-ca` | `PKI.BuildCA(...)` | Existing method. |
| `renew-ca` | `PKI.RenewCA(...)` | Existing method. |
| `gen-req` | `PKI.GenReq(...)` | Existing method. |
| `import-req` | `PKI.ImportReq(...)` | Existing typed PEM method; CLI file reading is input acquisition. |
| `sign-req` | `PKI.SignReq(...)` | Existing method. |
| `build-client-full` | `PKI.BuildClientFull(...)` | Existing method. |
| `build-server-full` | `PKI.BuildServerFull(...)` | Existing method. |
| `build-serverClient-full` | `PKI.BuildServerClientFull(...)` | Existing method. |
| `expire` | `PKI.Expire(name)` | New Easy-RSA lifecycle method. |
| `renew` | `PKI.Renew(...)` | Extended to archive the replaced certificate transactionally. |
| `revoke` | `PKI.Revoke(...)` | Refined to current-issued command semantics. |
| `revoke-issued` | `PKI.RevokeIssued(...)` | Explicit alias method over the same internal operation. |
| `revoke-expired` | `PKI.RevokeExpired(...)` | Extended to own lifecycle archiving. |
| `gen-crl` | `PKI.GenCRL()` | Persists PEM and DER artifacts through the backend. |
| `show-req` | `PKI.ShowReq(...)` | Returns a typed result that requires no ASN.1 parsing in the CLI. |
| `show-cert` | `PKI.ShowCert(...)` | Existing method. |
| `show-ca` | `PKI.ShowCA()` | Existing method. |
| `show-crl` | `PKI.ShowCRL()` | Existing method. |
| `show-expire` | `PKI.ShowExpiring(...)` | Existing method; CLI only selects typed arguments and formats. |
| `show-revoke` | `PKI.ShowRevoked()` | Existing method. |
| `show-eku` | `PKI.ShowEKU(nameOrPath)` | Extended with Easy-RSA path-first behavior. |
| `verify-cert` | `PKI.VerifyCert(...)` | Existing method. |
| `export-p12` | `PKI.ExportP12(...)` | Gains typed command options and artifact persistence. |
| `export-p7` | `PKI.ExportP7(...)` | Gains typed command options and artifact persistence. |
| `export-p8` | `PKI.ExportP8(...)` | Persists its fixed artifact. |
| `export-p1` | `PKI.ExportP1(...)` | Gains output-password support and persists its fixed artifact. |
| `gen-dh` | `PKI.GenDH(...)` | Persists `dh.pem`. |
| `update-db` | `PKI.UpdateDB()` | Existing method. |
| `set-pass` | `PKI.SetPass(...)` | Existing method. |
| `serial` | `PKI.Serial(...)` | Explicit wrapper around shared serial lookup. |
| `check-serial` | `PKI.CheckSerial(...)` | Existing method. |
| `display-dn` | `PKI.DisplayDN(form, path)` | New method with safe regular-file handling. |
| `rand` | `PKI.Rand(count, writer)` | New streaming method using `crypto/rand`. |

The mapping table is normative. Documentation and tests must contain the same 34 names.

### New and changed public signatures

The new utility and lifecycle entry points are:

```go
type InitPKIOptions struct {
    Reset bool
}

func (p *PKI) InitPKI(options InitPKIOptions) error
func (p *PKI) Expire(name string) error
func (p *PKI) RevokeIssued(name string, reason cert.RevocationReason) error
func (p *PKI) Serial(serial *big.Int) (*storage.IndexEntry, error)
func (p *PKI) DisplayDN(form DNForm, path string) (pkix.RDNSequence, error)
func (p *PKI) Rand(count int64, destination io.Writer) error
```

`DNForm` exports only `DNFormX509` and `DNFormRequest`. `Serial` delegates to `CheckSerial` and returns the same recursively deep-copied result.

`ShowEKU(nameOrPath string)` keeps its existing signature and gains path-first resolution. `ShowReq(name string)` keeps returning `*cert.CSR`; `cert.CSR` gains `Info() (*cert.RequestInfo, error)`. `RequestInfo` contains the entity name, raw ordered `pkix.RDNSequence`, copied DNS/IP/email SANs, a stable public-key description, and the `x509.SignatureAlgorithm`. The CLI formats that result without parsing ASN.1 itself.

Export methods use explicit option structs:

```go
type ExportP12Options struct {
    Password string
    NoCA     bool
    NoKey    bool
    Legacy   bool
}

type ExportP7Options struct {
    NoCA bool
}

func (p *PKI) ExportP12(name string, options ExportP12Options) ([]byte, error)
func (p *PKI) ExportP7(name string, options ExportP7Options) ([]byte, error)
func (p *PKI) ExportP8(name, password string) ([]byte, error)
func (p *PKI) ExportP1(name, password string) ([]byte, error)
```

`GenCRL` and `GenDH` keep returning `[]byte`; successful calls also persist their fixed artifacts. Existing call sites are migrated with the constructor and export signature changes.

## Command semantics that differ from current low-level methods

### Initialization

A backend can be constructed against an absent or empty namespace without mutating it. `PKI.InitPKI(InitPKIOptions{})` initializes a fresh Easy-RSA layout. If an owned PKI already exists, the method returns `storage.ErrConflict` unless `Reset` is true; reset removes the owned namespace transactionally and creates a fresh layout. The CLI maps an approved overwrite or batch invocation to `Reset: true`; the library never prompts.

`OpenWithFS` remains non-initializing. `NewWithFS` uses the backend's idempotent `EnsureLayout` operation for compatibility and never resets an existing PKI. It does not call the destructive `InitPKI` method.

Calling `InitPKI` on the legacy backend returns `storage.ErrReadOnly`. Calling it on a foreign non-empty namespace returns `storage.ErrForeignStorage` before any write, even when `Reset` is true.

### Expiry

Easy-RSA `expire` moves `issued/NAME.crt` to `expired/NAME.crt`. It does not alter the index status merely because the operator moved the file; the certificate remains valid until its actual expiry or a later database update.

`PKI.Expire(name)` implements that command behavior. The existing `ExpireCert(name)` remains an exported low-level index operation: it marks the index entry expired and never moves lifecycle files. The CLI calls `Expire`, not `ExpireCert`.

### Revocation

`PKI.Revoke` and `PKI.RevokeIssued` revoke the current issued certificate only. They archive the certificate, key, and CSR under `revoked/*_by_serial`, remove derived PKCS and inline artifacts, and update the index reason and time.

`PKI.RevokeExpired` revokes the certificate in `expired/NAME.crt` and archives only that certificate, preserving the current key and CSR.

These command methods do not generate a CRL. Easy-RSA instructs the operator to run `gen-crl` separately. `RevokeBySerial` remains a library extension with its existing update-and-regenerate-CRL behavior; command methods do not call it.

All name resolution uses the storage entity name rather than assuming that the subject common name equals the filename base.

### Renewal

`PKI.Renew` archives the current certificate under `renewed/issued/NAME.crt` before replacing it. An existing destination is a `storage.ErrConflict`; repeated renewal remains blocked until the old renewed certificate is revoked by the later lifecycle series.

The new certificate retains the existing key and current Easy-RSA extension semantics. The old certificate remains addressable by serial. Filesystem and memory backends retain enough renewal metadata for future `ShowRenewed` and `RevokeRenewed` methods.

The library retains its safer `StatusExpired` index marker for a superseded certificate. Future user-facing renewal reporting derives `V` or `E` from the archived certificate's actual expiry time rather than exposing that internal marker as an Easy-RSA incompatibility.

### Artifacts and exports

The library, not the CLI, writes these authoritative backend-relative artifacts:

- `crl.pem`
- `crl.der`
- `dh.pem`
- `private/NAME.p12`
- `issued/NAME.p7b`
- `private/NAME.p8`
- `private/NAME.p1`

Export methods continue to return generated bytes so direct callers can transmit or inspect them. Persistence is part of successful command-equivalent behavior.

Export variants use typed library options rather than CLI maps. Separate option types prevent invalid combinations:

- PKCS#12: output password, `NoCA`, `NoKey`, and `Legacy`;
- PKCS#7: `NoCA`;
- PKCS#8: output password;
- PKCS#1: output password.

Friendly-name customization remains explicitly unsupported. The library validates incompatible options even when called directly.

Public artifacts use public visibility and private-key-bearing artifacts use private visibility. The filesystem backend maps those classes to `0644` and `0600` on POSIX systems. Memory stores visibility with the bytes for contract tests.

### Inspection utilities

`PKI.ShowEKU(nameOrPath)` implements the existing path-first rule. A regular file is parsed as a certificate. A missing or non-regular path falls back to entity-name lookup. The method follows symlinks to regular files, avoids blocking on FIFOs where the platform supports non-blocking opens, and verifies the opened descriptor before reading.

`PKI.DisplayDN(form, path)` accepts `x509` or `req`, requires a regular file, parses `RawSubject`, and returns an ordered RDN representation that preserves repeated attributes, multi-valued sets, and unknown OIDs. The CLI only labels and prints those attributes.

`PKI.Rand(count, writer)` validates a positive signed 64-bit byte count, streams from `crypto/rand.Reader` through lowercase hexadecimal encoding, and appends one newline. It propagates source and destination errors.

`NewWithMemory(config)` constructs a complete in-memory `PKI`. The stateless `display-dn` and `rand` CLI adapters use a transient instance from this constructor, so they do not open, validate, create, or mutate a filesystem PKI merely to call methods on `PKI`.

`PKI.Serial` and `PKI.CheckSerial` return the same deep-copied index information. Batch silence and exit status remain CLI presentation behavior.

## Storage backend

### Aggregate boundary

`PKI` stores one cohesive `storage.Backend` instead of five unrelated dependencies. The backend exposes separate facets for:

- `KeyStorage`;
- `CSRStorage`;
- `IndexDB`;
- `SerialProvider`;
- `CRLHolder`;
- `ArtifactStorage`;
- `LifecycleStorage`.

The low-level facets remain exported and independently testable. The aggregate exists because a command operation must coordinate several facets under one lock and rollback boundary; it is not a duplicate command API.

`pki.New` accepts a `storage.Backend`. The filesystem, memory, and legacy packages expose backend constructors. `NewWithFS`, `OpenWithFS`, `NewWithMemory`, and `NewWithLegacyFSRO` remain convenience constructors.

The aggregate contract has one access path:

```go
type Backend interface {
    EnsureLayout() error
    Initialize(reset bool) error
    ReadOnly() bool
    View(func(Components) error) error
    Update(func(Components) error) error
}

type Components interface {
    Keys() KeyStorage
    CSRs() CSRStorage
    Index() IndexDB
    Serials() SerialProvider
    CRLs() CRLHolder
    Artifacts() ArtifactStorage
    Lifecycle() LifecycleStorage
}
```

`View` provides a consistent read boundary. `Update` owns the mutation lock and automatically commits a nil callback result or rolls back an error result. `EnsureLayout` creates only missing layout elements and never removes data. `Initialize(reset)` atomically checks the namespace, rejects an existing owned PKI when reset is false, and otherwise stages replacement so it can restore the old namespace if fresh-layout creation fails.

`ArtifactStorage` stores, reads, and deletes a backend-relative path together with copied bytes and a public/private visibility class. `LifecycleStorage` exposes transaction-scoped moves from issued to expired, issued to renewed, and issued/expired/renewed to revoked, plus renewed-certificate lookup. It does not update the index or generate certificates; `PKI` coordinates those domain operations through the other facets.

### Views and transactions

The backend provides two execution boundaries:

- a read view for a consistent non-mutating operation;
- an update transaction that commits when its callback returns nil and rolls back when the callback returns an error.

A transaction exposes the same storage facets plus lifecycle staging. `PKI` owns the operation order and domain decisions; the backend owns persistence, locking, staging, commit, and rollback.

All mutating `PKI` methods use an update transaction. Direct library calls therefore receive the same locking and rollback guarantees as CLI calls.

### Filesystem backend

The filesystem backend moves the following implementation out of `cmd/go-easyrsa`:

- sibling `.<pki-name>.go-easyrsa.lock` acquisition;
- canonical root resolution;
- `os.Root` confinement;
- non-blocking regular-file opens on supported Unix targets;
- source identity checks;
- no-clobber destination creation;
- temporary writes, `fsync`, and atomic rename;
- lifecycle staging and rollback;
- artifact cleanup after revocation.

The transaction keeps enough identity and backup information to undo its own writes if a later index or CRL operation fails. Rollback never deletes or overwrites a path whose identity changed after staging. Commit and rollback errors are joined so the caller sees both the original failure and any cleanup failure.

### Memory backend

The memory backend adds lifecycle locations, renewal history, revoked history, and named artifacts to its shared state. An update transaction works on a deep copy and swaps it into place only after success. Returned pairs, entries, RDN values, and artifact bytes are deep copies.

Its observable command semantics match the filesystem backend even though it has no physical paths. Backend-relative artifact names remain the same.

### Legacy backend

The legacy backend remains read-only. Read views support operations that the legacy layout can supply. Initialization, artifact writes, lifecycle moves, serial advancement, index changes, and other mutation attempts return `storage.ErrReadOnly` before any state change.

## Error model

Existing sentinels remain authoritative:

- `storage.ErrNotFound` for absent entities or artifacts;
- `storage.ErrConflict` for occupied lifecycle or no-clobber destinations;
- `storage.ErrReadOnly` for legacy mutation attempts;
- `storage.ErrForeignStorage` for an existing namespace that the backend does not own.

Typed input validation also occurs in the library. Direct callers cannot bypass name, size, count, format, option-combination, or path-safety checks by avoiding the CLI.

The CLI may translate a known result into a silent batch exit, but it does not replace or reinterpret storage and cryptographic failures.

## CLI reduction

After the refactor, production code in `cmd/go-easyrsa` must not contain:

- lifecycle session or staging types;
- flock or `os.Root` mutation code;
- atomic PKI artifact writers;
- PKCS#1, PKCS#7, PKCS#8, or PKCS#12 encoding;
- certificate or CSR ASN.1 parsing for command behavior;
- cryptographic random generation;
- path-first certificate classification.

The following remain appropriate in the CLI:

- Cobra command registration and argument counts;
- parsing Easy-RSA textual aliases such as certificate types and revocation reasons;
- environment/config precedence;
- conversion to typed options;
- reading the unambiguous source file for `import-req`;
- formatting typed subjects, summaries, artifact paths, and status lines;
- batch-specific silence and exit codes.

The existing CLI lifecycle, artifact, and platform-open files are removed or moved into the root module once no production handler uses them.

## Module dependency flow

The root library changes first and is committed and pushed. The exact pushed commit is resolved as a `v2.2.1-0...` pseudo-version. `cmd/go-easyrsa/go.mod` then advances to that version without a local `replace` directive.

If a later root correction is required, the root commit is pushed and the CLI pseudo-version is advanced again. The nested CLI must be installable from the final branch commit outside the repository.

Dependencies move to the module that owns the implementation. For example, filesystem locking belongs in the root module after lifecycle moves out of the CLI, while PKCS libraries cease to be direct CLI dependencies when export encoding moves into `pki`.

## Testing strategy

### Backend contract suites

One shared writable contract runs against filesystem and memory backends. It covers:

- initialization and ownership checks;
- artifact bytes, visibility, replacement, and failure preservation;
- current, expired, renewed, and revoked lifecycle locations;
- entity names that differ from certificate common names;
- transaction commit and rollback;
- deep-copy isolation;
- conflict and not-found behavior;
- concurrent mutation exclusion.

A separate legacy contract proves that reads remain available and every mutation returns `storage.ErrReadOnly` without changing raw files.

### Direct PKI tests

Every row in the 34-command method table has direct library coverage. Tests exercise typed options and verify the command-equivalent state without invoking Cobra.

Failure injection covers staging, source replacement, artifact write, storage replacement, index update, transaction commit, and rollback. Tests compare raw filesystem trees before and after failed operations.

### CLI adapter tests

For representative creation, inspection, lifecycle, export, and utility commands, tests perform the same operation once through `PKI` and once through the CLI, then compare typed results and raw backend state.

An architecture test parses production imports under `cmd/go-easyrsa` and rejects reintroduction of PKCS encoders, ASN.1 command logic, flock, lifecycle staging, artifact writing, and random generation.

### Compatibility and verification

The canonical 34-command E2E suite continues to pass against pinned Easy-RSA v3.2.6 with identical argv and no skips or expected failures. The command count remains 34 verified and 10 deferred.

The final branch must also pass:

- all four module test and vet suites on Go 1.25.13 and 1.26.6;
- root and CLI E2E on both toolchains;
- race tests for root storage/PKI and CLI adapter tests;
- Windows and Linux cross-compilation for affected packages;
- `golangci-lint v2.12.2`;
- `govulncheck v1.7.0` for all modules;
- `actionlint`;
- idempotent `go mod tidy` and `go mod verify`;
- standalone `go install` from the pushed final branch commit.

## Delivery boundaries

The work is one foundational PR with logical commits:

1. backend transaction model and public `PKI` methods;
2. pushed root pseudo-version in the nested CLI module;
3. CLI reduction to argument and output adapters;
4. backend/API contracts, compatibility E2E, and documentation.

The PR does not add command names, merge itself, create tags, or publish a release. After it is reviewed and merged, the next command series adds `PKI.ShowRenewed` and `PKI.RevokeRenewed` on top of the renewal storage introduced here.

## Acceptance criteria

- All 34 registered commands map explicitly to public methods on `*PKI`.
- Direct library calls reproduce the supported Easy-RSA operation without hidden CLI business logic.
- Filesystem and memory backends pass the same writable command contract.
- Legacy mutations fail with `storage.ErrReadOnly` and leave files unchanged.
- Every mutating method uses backend-controlled locking and rollback.
- Read-only methods never initialize or mutate storage.
- The CLI contains no lifecycle, artifact, PKCS, ASN.1 command, or random-generation implementation.
- The nested CLI has no local root-module replacement and installs from the pushed branch.
- The verified matrix remains 34 commands with 10 deferred.
- Local and GitHub checks pass on Go 1.25.13 and 1.26.6.
- No release tags are created.

# Renewed certificate lifecycle commands

## Status

Approved in the design discussion. The written specification awaits user review before implementation planning.

## Background

The CLI currently verifies 34 Easy-RSA v3.2.6 command names and defers 10. The foundational PKI command-method work moved lifecycle rules into `*pki.PKI`, introduced transactional storage backends, and made `renew` archive the replaced certificate at `renewed/issued/NAME.crt`.

That archive is the prerequisite for the next command pair:

- `show-renew [common-name]` reports renewed certificates that have not been revoked;
- `revoke-renewed <name> [reason]` revokes the archived certificate while preserving the current replacement's key and request.

Easy-RSA also recognizes historical renewal archives at `renewed/certs_by_serial/SERIAL.crt`. `show-renew` marks those entries as requiring `rewind-renew` before revocation. Easy-RSA v3.2.6 does not register a `rewind-renew` command, so this feature reports that state but does not mutate it.

## Goals

- Add public `PKI.ShowRenewed` and `PKI.RevokeRenewed` methods.
- Register `show-renew` and `revoke-renewed` as thin CLI adapters.
- Report both current named renewal archives and historical serial-based archives.
- Preserve filesystem, memory, and legacy backend behavior behind one storage contract.
- Revoke named renewal archives atomically without changing the current certificate, key, or CSR.
- Preserve Easy-RSA's explicit `gen-crl` step.
- Accept every Easy-RSA revocation reason, including `certificateHold`.
- Raise the verified command matrix from 34 to 36 and reduce the deferred list from 10 to 8.

## Non-goals

- Implementing `rewind-renew` or making serial-based historical archives directly revocable.
- Adding any of the other eight deferred commands.
- Matching Easy-RSA banners, prompts, warnings, or OpenSSL prose byte for byte.
- Changing the positive-compatibility contract or allowing E2E skips and expected failures.
- Creating a release, moving a tag, or merging the feature PR.

## Compatibility contract

The feature keeps the existing positive-compatibility rules:

- both CLIs receive the same canonical upstream-valid argv;
- successful upstream scenarios must succeed in `go-easyrsa`;
- status, serial, expiry, common name, lifecycle location, index state, CRL state, and retained assets are compared semantically;
- rejection wording and interactive prompts need not match;
- filesystem safety may reject unsafe symlinks, special files, and inconsistent archives more strictly than upstream.

The pinned authority remains Easy-RSA v3.2.6 at commit `0d746eec3f06210ae1710d17b9c8d38428058e19`.

## Public PKI API

The root module adds this result type:

```go
type RenewalInfo struct {
    Name           string
    Serial         *big.Int
    Status         storage.CertStatus
    ExpiresAt      time.Time
    CommonName     string
    CertificatePEM []byte
    RequiresRewind bool
}
```

It also adds two methods:

```go
func (p *PKI) ShowRenewed() ([]RenewalInfo, error)
func (p *PKI) RevokeRenewed(name string, reason cert.RevocationReason) error
```

`RenewalInfo` has these guarantees:

- `Serial` and `CertificatePEM` are deep copies;
- `Status` is only `storage.StatusValid` or `storage.StatusExpired`;
- status comes from the archived certificate's actual `NotAfter` value at call time, not from the internal superseded index marker;
- `ExpiresAt` is the parsed certificate expiry;
- `CommonName` comes from the matching index entry;
- `Name` is the named archive's storage name, or the matching common name when a historical serial archive has no filename-based entity name;
- `RequiresRewind` is true only for `renewed/certs_by_serial`.

The method returns values rather than storage snapshot types. Direct callers do not need to know the backend layout or parse certificates to reproduce command behavior.

## Storage contract

### Focused renewal query

`storage.LifecycleStorage` gains this focused query:

```go
type RenewalArchiveSource string

const (
    RenewalArchiveIssued   RenewalArchiveSource = "issued"
    RenewalArchiveBySerial RenewalArchiveSource = "certs_by_serial"
)

type RenewalArchive struct {
    Name           string
    Serial         *big.Int
    CertificatePEM []byte
    Source         RenewalArchiveSource
}

ListRenewed() ([]RenewalArchive, error)
```

`Name` is the basename of a named archive and is empty for a serial archive, whose path does not encode the original entity name. The two sources map to:

- `RenewalArchiveIssued`: `renewed/issued/NAME.crt`;
- `RenewalArchiveBySerial`: `renewed/certs_by_serial/SERIAL.crt`.

The focused query avoids reading expired and revoked lifecycle records, archived private keys, and archived CSRs merely to serve `show-renew`.

### Filesystem backend

The filesystem implementation opens both renewal directories through the confined backend root. It:

- accepts only `.crt` regular files;
- rejects symlinks, directories, FIFOs, sockets, and descriptor replacement;
- validates named archive basenames;
- parses serial archive filenames as positive hexadecimal serials;
- verifies that a serial filename matches the certificate serial;
- detects duplicate serials, including differently cased filenames on case-sensitive filesystems;
- returns copied bytes and deterministic records.

Unrelated non-certificate files are ignored. A certificate-shaped unsafe or malformed entry returns an error rather than being followed or silently treated as valid.

### Memory backend

The memory backend stores named and serial-based renewal archives separately. `View` returns deep copies. `Update` still publishes a private clone only after commit. Existing `MoveIssuedToRenewed`, `GetRenewedCertificate`, and `MoveRenewedToRevoked` operate only on the named archive collection.

### Legacy backend

The legacy backend implements the same confined read query for both directories. `ShowRenewed` therefore works against legacy PKIs. Mutation still fails at the backend boundary with `storage.ErrReadOnly` before any callback or filesystem write.

### Read-only wrapper

The read-only lifecycle wrapper delegates `ListRenewed`. It continues to reject every mutation with `storage.ErrReadOnly`.

## Snapshot representation

`storage.LifecycleRecord` gains a `RenewalSource RenewalArchiveSource` field used only by entries in `LifecycleState.Renewed`.

- An empty source is interpreted as the existing named archive form for compatibility with existing in-memory values.
- Export records the exact named or serial source.
- Replace restores named entries to `renewed/issued/NAME.crt` and historical entries to `renewed/certs_by_serial/SERIAL.crt`.
- Snapshot import never rewinds a historical entry.
- Validation rejects unsupported sources, duplicate locations, duplicate serials, and source/path inconsistencies.

Round trips across filesystem and memory preserve `RequiresRewind`. Legacy export includes the source even though legacy import remains read-only.

## `PKI.ShowRenewed` behavior

`ShowRenewed` runs inside one backend `View` and follows Easy-RSA's index-driven report semantics.

1. Read renewal archive metadata with `ListRenewed`.
2. Parse each referenced certificate and validate its serial.
3. Read index entries in index order.
4. Consider only `V` and `E` index entries; revoked entries are not reported.
5. Match a named archive by the index entry's `CommonName` and exact certificate serial.
6. Match a historical archive by the index entry's exact serial.
7. Reject a state where both sources match the same index entry with `storage.ErrConflict`.
8. Build `RenewalInfo`, deriving `V` or `E` from actual expiry.
9. Return results in index order.

A named archive whose filename differs from the matching index common name is not reported. This reproduces Easy-RSA v3.2.6, which constructs the named archive path from the index CN even though its help calls the optional argument a file-name base.

An archive without a matching live index entry is not a renewed, unrevoked report entry. Unsafe files, malformed certificates, invalid serial filenames, duplicate serials, and contradictory matching records return an error. An empty report succeeds.

## `PKI.RevokeRenewed` behavior

`RevokeRenewed` runs inside one backend `Update`.

1. Validate the entity name and revocation reason.
2. Read `renewed/issued/NAME.crt`; do not fall back to the serial archive directory.
3. Parse the certificate and reject a self-signed certificate.
4. Move it to `revoked/certs_by_serial/SERIAL.crt` through `MoveRenewedToRevoked`.
5. Remove name-based PKCS and inline artifacts, matching Easy-RSA's revoke behavior.
6. Update the archived certificate's index entry to `R` with the selected reason and revocation time.

The transaction preserves these invariants:

- the current replacement certificate remains at `issued/NAME.crt`;
- the current private key and CSR remain in place;
- no CRL is generated or changed;
- destination conflicts return `storage.ErrConflict` without source loss;
- archive, artifacts, and index all roll back after any callback or commit failure;
- the successful move frees `renewed/issued/NAME.crt`, so the current certificate can later be renewed again.

A historical serial-based archive is intentionally not addressable by this method. If no named archive exists, the method returns `storage.ErrNotFound` even when `ShowRenewed` reports a `RequiresRewind` record.

## Revocation reasons

Easy-RSA v3.2.6 accepts `certificateHold`, but the current Go enum and CLI parser stop at `cessationOfOperation`. This feature adds:

```go
const ReasonCertificateHold RevocationReason = 6
```

The root library accepts it, the filesystem index reads and writes `certificateHold`, CRL generation emits reason code 6, and the CLI accepts the upstream forms `ch`, `cer*`, and `certificateHold`.

The parser also keeps the existing upstream-compatible reason families:

- `us`, `uns*`;
- `kc`, `key*`;
- `cc`, `ca*`;
- `ac`, `aff*`;
- `ss`, `sup*`;
- `co`, `ces*`;
- `ch`, `cer*`.

This positive extension applies consistently to all revoke commands rather than only `revoke-renewed`.

## CLI adapters

The CLI registers:

```text
show-renew [common-name]
revoke-renewed <name> [reason]
```

### `show-renew`

The adapter:

1. opens the PKI through the existing non-initializing read-only path;
2. calls `PKI.ShowRenewed()`;
3. optionally filters results by exact `CommonName`;
4. prints status, uppercase serial, expiry, and common name;
5. prefixes historical entries with `***`.

The optional argument deliberately follows Easy-RSA's actual CN filter. A missing target produces no result lines and exits successfully. Exact banners and warning prose are not required.

Date formatting may follow the stable UTC OpenSSL-style shape used by Easy-RSA, but the compatibility tests parse the value and compare the instant rather than raw locale-dependent text.

### `revoke-renewed`

The adapter parses the optional reason with the shared revoke parser, opens a writable PKI, and calls `PKI.RevokeRenewed`. It owns no lifecycle paths, certificate parsing, archive movement, index mutation, or CRL behavior.

The existing CLI architecture guard remains in force.

## Command matrix and documentation

The verified table gains:

- `show-renew`;
- `revoke-renewed`.

The matrix becomes 36 verified commands and eight deferred commands:

- `self-sign-server`, `self-sign-client`;
- `inline`;
- `import-ca`, `import-tls-key`;
- `gen-tls-auth-key`, `gen-tls-crypt-key`;
- `write`.

README and both parity documents must agree on the counts and lifecycle semantics. They must not claim a release.

## Nested module dependency flow

The root API and storage changes are committed and pushed before CLI production code imports them. The CLI module then pins the exact pushed root commit through a Go pseudo-version.

`cmd/go-easyrsa/go.mod` must not contain a local `replace`. Any later root correction requires another push and a new exact pseudo-version before final verification.

## Test strategy

### Storage contracts

Shared and backend-specific tests cover:

- named and serial archive listing;
- deep-copy isolation;
- deterministic results;
- exact source preservation through snapshot round trips;
- malformed serial filenames and filename/certificate mismatch;
- duplicate serials and both-source conflicts;
- symlink, directory, FIFO, and descriptor replacement rejection;
- read-only legacy mutation failure;
- transaction rollback and destination conflict behavior.

### PKI tests

Cross-backend tests cover:

- normal `renew` followed by `ShowRenewed`;
- historical `RequiresRewind` results;
- actual-expiry `V` and `E` status derivation;
- index-order output and exact CN behavior;
- mutation of returned serial and PEM without backend aliasing;
- successful `RevokeRenewed`;
- preservation of current certificate, key, and CSR;
- removal and rollback of derived artifacts;
- unchanged CRL until `GenCRL`;
- re-renewal after revocation frees the named slot;
- self-signed, missing, malformed, already revoked, and conflicting inputs;
- `certificateHold` index and CRL encoding.

### CLI tests

Ordinary adapter tests cover registration, argument counts, CN filtering, historical markers, date and serial formatting, reason aliases, read-only opening, error propagation, and the absence of direct lifecycle logic.

Direct-PKI versus CLI tests compare index, lifecycle, artifact, key, CSR, and CRL state from identical inputs.

### Authoritative E2E

Both implementations receive identical canonical argv for:

1. initialization and CA creation;
2. certificate creation and renewal;
3. unfiltered and CN-filtered `show-renew`;
4. `revoke-renewed` with representative reasons, including `certificateHold`;
5. an empty report after revocation;
6. explicit `gen-crl`;
7. a second renewal after the old renewed certificate is revoked.

A separate fixture moves a valid renewal archive into `renewed/certs_by_serial/SERIAL.crt` in both PKIs and compares the `***` report semantics. It does not invent a successful direct revocation path for that state.

Mixed-producer tests exercise Easy-RSA renewal followed by Go inspection/revocation and Go renewal followed by Easy-RSA inspection/revocation. Tests compare meaningful output fields and exact lifecycle artifacts without allowlists, skips, or expected failures.

## Verification

Final verification covers all four modules with Go 1.25.13 and 1.26.6:

- ordinary tests and `go vet`;
- root and CLI E2E;
- targeted storage, PKI, and CLI race suites;
- `golangci-lint` v2.12.2;
- `govulncheck` v1.7.0;
- `actionlint`;
- Linux, Windows, and relevant cross-compilation checks;
- nested-module tidy, verify, and no-`replace` checks;
- submodule pin and diff checks;
- standalone `go install` from the final pushed commit.

GitHub checks must pass before the work is reported ready. Merge, tags, and release remain separate user decisions.

## Acceptance criteria

- `PKI.ShowRenewed` reports named and historical unrevoked renewal archives as typed deep-copied values.
- User-facing renewal status reflects actual certificate expiry.
- Historical archives are marked `RequiresRewind` and are not directly revocable.
- `PKI.RevokeRenewed` atomically archives and revokes only the old renewed certificate.
- Current certificate, key, and CSR remain unchanged.
- Revoke does not generate a CRL.
- Filesystem and memory pass the same writable behavior; legacy supports show and rejects revoke.
- `certificateHold` works through API, index, CLI, and generated CRLs.
- CLI production code only parses, delegates, formats, and maps errors.
- The authoritative matrix passes with 36 verified commands and eight deferred commands.
- The CLI uses a pushed root pseudo-version without `replace`.
- No unrelated deferred command, release, tag, or merge is included.

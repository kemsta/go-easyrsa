# PKI migration

`go-easyrsa` provides a storage-agnostic migration path built on top of public `pki` APIs.

At the library level this is exposed as:
- `(*pki.PKI).ExportSnapshot()`
- `(*pki.PKI).ExportPairs(yield)`
- `(*pki.PKI).ImportSnapshot(snapshot, stream)`
- `migration.Migrate(source, target)`

At the CLI level this is exposed by the dedicated migrator submodule under `cmd/go-easyrsa-migrate`.

## Why it is structured this way

The migrator is intentionally split into two layers:

1. **Library layer**
   - snapshot export/import in `pki`
   - generic migration orchestration in `migration`
2. **CLI layer**
   - Cobra-based command parsing in a separate submodule

This keeps the main library free from a CLI dependency while still allowing an official migration command.

## Supported migration model

The migration pipeline is designed to be backend-agnostic.

Today the main practical use-case is:
- `legacy-fs -> fs`

But the same snapshot pipeline is intended to support:
- `fs -> memory`
- `memory -> fs`
- future custom backends

## Snapshot contents

The migration format is split in two parts:

1. **Metadata snapshot**
   - CA name
   - index entries / certificate statuses
   - CRL
   - next serial
2. **Pair stream**
   - certificate pairs are streamed separately via `ExportPairs(...)`

This keeps memory usage bounded even when the PKI contains a large number of certificate/key pairs.

## CLI

The CLI lives in a separate module:

```text
cmd/go-easyrsa-migrate
```

Build it from that directory:

```bash
cd cmd/go-easyrsa-migrate
go build
```

Run a legacy-to-current migration:

```bash
go-easyrsa-migrate --from /path/to/legacy-pki --to /path/to/new-pki
```

Available flags:
- `--from` — source PKI directory
- `--to` — target PKI directory
- `--from-type` — source backend type (`legacy-fs` or `fs`)
- `--to-type` — target backend type (`fs`)
- `--ca-name` — storage name of the CA entry in the source PKI (default: `ca`)

Defaults:
- `--from-type=legacy-fs`
- `--to-type=fs`

## Safety model

Migration is **copy-based**:
- source PKI is never modified
- target PKI must be a new or empty directory

The migrator refuses to write into a non-empty target directory.

## Current easy-rsa layout materialization

When importing into the current filesystem backend:
- all certificates are written to `certs_by_serial/`
- latest certificate per name becomes the named cert in `issued/` or `ca.crt`
- latest key per name becomes the named key in `private/`
- statuses are written to `index.txt`
- the serial file is set to the next available serial

## Legacy notes

For legacy v1 PKIs, see also [legacy.md](legacy.md).

# Legacy v1 layout support

`go-easyrsa` supports opening PKIs created by the old v1 filesystem storage in **read-only** mode.

Use this backend when you need to inspect, verify, or export data from an existing v1 PKI before migrating it to the current easy-rsa-compatible layout.

## Constructor

```go
p, err := pki.NewWithLegacyFSRO("/path/to/pki", pki.Config{})
```

## Legacy layout

The v1 storage kept certificates and keys in per-name directories:

```text
pkiDir/<name>/<serial>.crt
pkiDir/<name>/<serial>.key
pkiDir/crl.pem
pkiDir/serial
```

Unlike the current filesystem backend, v1 did **not** store:
- `index.txt`
- `issued/<name>.crt`
- `private/<name>.key`
- `certs_by_serial/<serial>.pem`
- `reqs/`

## What works

The legacy backend supports read-only operations over the old layout.

### Reading certificates
- `ShowCA()`
- `ShowCert(name)`
- `ShowCRL()`
- `IsRevoked(serial)`
- `VerifyCert(name)`

### Inspection
- `ShowRevoked()`
- `ShowExpiring(days)`

### Export
- `ExportP12(name, password)`
- `ExportP7(name)`
- `ExportP8(name, password)`
- `ExportP1(name)`

### Storage semantics
- `GetByName(name)` returns **all** historical certificates stored for that name
- `GetLastByName(name)` returns the certificate with the highest serial
- `GetBySerial(serial)` resolves a certificate directly from the legacy tree

## What does not work

All mutating flows are intentionally unsupported and return `storage.ErrReadOnly`.

This includes:
- `BuildCA()`
- `GenReq()`
- `ImportReq()`
- `SignReq()`
- `BuildClientFull()` / `BuildServerFull()` / `BuildServerClientFull()`
- `Renew()` / `RenewCA()`
- `Revoke()` / `RevokeBySerial()` / `RevokeExpired()`
- `GenCRL()`
- `UpdateDB()`
- `SetPass()`
- direct mutating storage operations such as `Put`, `Delete*`, `PutCSR`, `Next`, CRL `Put`

## How status is reconstructed

Because v1 had no `index.txt`, the legacy backend builds a synthetic in-memory view of certificate status.

Status is derived as follows:
- `revoked` — certificate serial is present in `crl.pem`
- `expired` — certificate `NotAfter` is in the past
- `valid` — everything else

No `index.txt` is created or modified.

## Important limitations

### 1. Read-only by design

The backend is meant for compatibility and migration, not as a permanent writable storage.

If you need issuance, renewal, revocation, CRL generation, or database maintenance, migrate the PKI to the current layout first.

### 2. No full renewal history semantics from v1

Since v1 had no certificate database, the backend cannot always infer that an older certificate was superseded by a later renewal.

That means an older certificate may still appear as `valid` if it is:
- not expired, and
- not listed in the CRL

This is expected for the read-only compatibility mode.

### 3. Name semantics follow the legacy directory name

The legacy layout stores data under `pkiDir/<name>/...`.

That directory name is treated as the storage entity name. The old layout does not preserve newer v2 semantics where storage name and certificate CN may intentionally differ.

## Recommended migration path

1. Open the old PKI with `pki.NewWithLegacyFSRO(...)`
2. Read/verify/export the data you need
3. Run the migration CLI/tool (see [migration.md](migration.md)) to rewrite data into the current easy-rsa-compatible layout
4. Re-open the migrated PKI with `pki.NewWithFS(...)`

## Summary

Use the legacy backend to safely **read** old v1 PKIs.

Use the current filesystem backend for all **read-write** PKI lifecycle operations.

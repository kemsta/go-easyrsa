# easy-rsa Command Parity

This document tracks the correspondence between Easy-RSA commands and public
`*pki.PKI` methods. The Cobra CLI in `cmd/go-easyrsa` is a thin adapter over
these methods: it parses argv/environment input, builds typed options, formats
results, and maps exit status. Crypto, ASN.1, PKCS, lifecycle, locking, path
handling, randomness, and artifact persistence live in the root library.

The 36-command positive-compatibility subset is verified by E2E against pinned
Easy-RSA v3.2.6. Eight upstream commands remain explicitly deferred. For detailed
CLI flag and environment coverage, see
[`docs/go-easyrsa-cli-parity.md`](go-easyrsa-cli-parity.md).

## Command → method mapping

| Easy-RSA command | Public PKI method |
|---|---|
| `init-pki` | `PKI.InitPKI(options)` |
| `build-ca` | `PKI.BuildCA(options...)` |
| `renew-ca` | `PKI.RenewCA(options...)` |
| `gen-req` | `PKI.GenReq(name, options...)` |
| `import-req` | `PKI.ImportReq(name, csrPEM)` |
| `sign-req` | `PKI.SignReq(name, type, options...)` |
| `build-client-full` | `PKI.BuildClientFull(name, options...)` |
| `build-server-full` | `PKI.BuildServerFull(name, options...)` |
| `build-serverClient-full` | `PKI.BuildServerClientFull(name, options...)` |
| `expire` | `PKI.Expire(name)` |
| `renew` | `PKI.Renew(name, options...)` |
| `revoke` | `PKI.Revoke(name, reason)` |
| `revoke-issued` | `PKI.RevokeIssued(name, reason)` |
| `revoke-expired` | `PKI.RevokeExpired(name, reason)` |
| `revoke-renewed` | `PKI.RevokeRenewed(name, reason)` |
| `gen-crl` | `PKI.GenCRL()` |
| `show-req` | `PKI.ShowReq(name)` and `CSR.Info()` |
| `show-cert` | `PKI.ShowCert(name)` |
| `show-ca` | `PKI.ShowCA()` |
| `show-crl` | `PKI.ShowCRL()` |
| `show-expire` | `PKI.ShowExpiring(days)` |
| `show-revoke` | `PKI.ShowRevoked()` |
| `show-renew` | `PKI.ShowRenewed()` |
| `show-eku` | `PKI.ShowEKU(nameOrPath)` |
| `verify-cert` | `PKI.VerifyCert(name)` |
| `export-p12` | `PKI.ExportP12(name, options)` |
| `export-p7` | `PKI.ExportP7(name, options)` |
| `export-p8` | `PKI.ExportP8(name, password)` |
| `export-p1` | `PKI.ExportP1(name, password)` |
| `gen-dh` | `PKI.GenDH(bits)` |
| `update-db` | `PKI.UpdateDB()` |
| `set-pass` | `PKI.SetPass(name, oldPassword, newPassword)` |
| `serial` | `PKI.Serial(serial)` |
| `check-serial` | `PKI.CheckSerial(serial)` |
| `display-dn` | `PKI.DisplayDN(form, path)` |
| `rand` | `PKI.Rand(count, writer)` |

## Library-owned command semantics

- `InitPKI` distinguishes fresh initialization from an explicit owned-PKI
  reset; foreign storage is never replaced.
- `Expire`, `Renew`, `RevokeIssued`, `RevokeExpired`, and `RevokeRenewed`
  perform Easy-RSA file lifecycle changes and index updates in backend
  transactions.
- `ShowRenewed` returns typed `RenewalInfo` values containing name, serial,
  actual-expiry `V`/`E` status, expiry, common name, detached certificate PEM,
  and `RequiresRewind`. Historical `renewed/certs_by_serial` records are marked
  for rewind and remain report-only.
- `RevokeRenewed` archives only the old renewed certificate. It preserves the
  current replacement certificate, private key, and CSR.
- Revoke methods do not implicitly generate a CRL. `gen-crl` is a separate
  operation, matching Easy-RSA.
- `GenCRL`, `GenDH`, and export methods persist their fixed Easy-RSA artifacts
  and return the exact bytes written.
- Read views are non-mutating. `display-dn` and `rand` use transient memory PKIs
  and do not open or create a filesystem PKI.

Additional library extensions without direct Easy-RSA command equivalents:

| Operation | Method |
|---|---|
| Index-only expiry | `PKI.ExpireCert(name)` |
| Revoke by serial and regenerate CRL | `PKI.RevokeBySerial(serial, reason)` |
| Check CRL revocation | `PKI.IsRevoked(serial)` |
| Snapshot migration | `PKI.ExportSnapshot()` / `PKI.ImportSnapshot(...)` |
| Orphan cleanup | `PKI.Clean()` |

## Easy-RSA reference

The pinned reference is available as the `subprojects/easy-rsa` git submodule
and is used by authoritative E2E tests:

```text
v3.2.6
0d746eec3f06210ae1710d17b9c8d38428058e19
```

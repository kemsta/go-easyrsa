# easy-rsa Command Parity

This document tracks the correspondence between easy-rsa commands and go-easyrsa library methods.

The repository also contains a Cobra-based `go-easyrsa` CLI in
`cmd/go-easyrsa`, implemented on top of these methods. Its 34-command
positive-compatibility subset is verified by E2E against the pinned Easy-RSA
v3.2.6 reference. Ten remaining upstream commands are explicitly deferred
rather than claimed as complete parity.

For command/flag/env parity tracking of the CLI itself, see
[`docs/go-easyrsa-cli-parity.md`](go-easyrsa-cli-parity.md).

## Command → Method Mapping

| easy-rsa command            | v2 status                           |
|-----------------------------|-------------------------------------|
| `build-ca`                  | ✅ `PKI.BuildCA()`                  |
| `renew-ca`                  | ✅ `PKI.RenewCA()`                  |
| `gen-req [name]`            | ✅ `PKI.GenReq(name, opts)`         |
| `import-req`                | ✅ `PKI.ImportReq(name, csrPEM)`    |
| `sign-req [type] [name]`    | ✅ `PKI.SignReq(name, type, opts)`  |
| `build-client-full`         | ✅ `PKI.BuildClientFull(name, opts)`|
| `build-server-full`         | ✅ `PKI.BuildServerFull(name, opts)`|
| `build-serverClient-full`   | ✅ `PKI.BuildServerClientFull()`    |
| `expire [name]`             | ✅ `PKI.ExpireCert(name)`           |
| `renew [name]`              | ✅ `PKI.Renew(name, opts)`          |
| `revoke` / `revoke-issued` | ✅ `PKI.Revoke(name, reason)`       |
| `revoke-expired [name]`     | ✅ `PKI.RevokeExpired(name, reason)`|
| `gen-crl`                   | ✅ `PKI.GenCRL()`                   |
| `show-req [name]`           | ✅ `PKI.ShowReq(name)`              |
| `show-cert [name]`          | ✅ `PKI.ShowCert(name)`             |
| `show-ca`                   | ✅ `PKI.ShowCA()`                   |
| `show-crl`                  | ✅ `PKI.ShowCRL()`                  |
| `show-expire [days]`        | ✅ `PKI.ShowExpiring(days)`         |
| `show-revoke`               | ✅ `PKI.ShowRevoked()`              |
| `show-eku [name]`           | ✅ `PKI.ShowEKU(name)`              |
| `verify-cert [name]`        | ✅ `PKI.VerifyCert(name)`           |
| `export-p12`                | ✅ `PKI.ExportP12(name, password)`  |
| `export-p7`                 | ✅ `PKI.ExportP7(name)`             |
| `export-p8`                 | ✅ `PKI.ExportP8(name, password)`   |
| `export-p1`                 | ✅ `PKI.ExportP1(name)`             |
| `gen-dh`                    | ✅ `PKI.GenDH(bits)`                |
| `update-db`                 | ✅ `PKI.UpdateDB()`                 |
| `set-pass [name]`           | ✅ `PKI.SetPass(name, old, new)`    |
| `serial` / `check-serial`   | ✅ `PKI.CheckSerial(serial)`        |
| `init-pki`                  | via `NewWithFS()` (auto-creates dirs)|

The CLI adds Easy-RSA filesystem lifecycle behavior around several methods:
`expire` moves `issued/NAME.crt` to `expired/NAME.crt`, and revoke commands
archive files under `revoked/*_by_serial`. It also implements the stateless
`display-dn` and `rand` utilities. The library methods retain backend-neutral
index/CRL semantics and therefore are not byte-for-byte CLI implementations of
those shell commands.

Additional library extensions (no easy-rsa equivalent):

| Operation       | Method                              |
|-----------------|-------------------------------------|
| Revoke by serial| `PKI.RevokeBySerial(serial, reason)`|
| Check revoked   | `PKI.IsRevoked(serial)`             |

## easy-rsa Reference

The easy-rsa binary is available as a git submodule at `subprojects/easy-rsa/`.
It is used as a reference implementation and for e2e testing.

```
subprojects/easy-rsa/easyrsa3/easyrsa --help
```

See `docs/design.md` for the v2 library architecture.

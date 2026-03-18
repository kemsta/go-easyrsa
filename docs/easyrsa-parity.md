# easy-rsa Command Parity

This document tracks the correspondence between easy-rsa commands and go-easyrsa library methods.

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
| `revoke-issued [name]`      | ✅ `PKI.Revoke(name, reason)`       |
| `revoke-expired [name]`     | ✅ `PKI.RevokeExpired(name, reason)`|
| `gen-crl`                   | ✅ `PKI.GenCRL()`                   |
| `show-cert [name]`          | ✅ `PKI.ShowCert(name)`             |
| `show-ca`                   | ✅ `PKI.ShowCA()`                   |
| `show-crl`                  | ✅ `PKI.ShowCRL()`                  |
| `show-expire [days]`        | ✅ `PKI.ShowExpiring(days)`         |
| `show-revoke`               | ✅ `PKI.ShowRevoked()`              |
| `verify-cert [name]`        | ✅ `PKI.VerifyCert(name)`           |
| `export-p12`                | ✅ `PKI.ExportP12(name, password)`  |
| `export-p7`                 | ✅ `PKI.ExportP7(name)`             |
| `export-p8`                 | ✅ `PKI.ExportP8(name, password)`   |
| `export-p1`                 | ✅ `PKI.ExportP1(name)`             |
| `gen-dh`                    | ✅ `PKI.GenDH(bits)`                |
| `update-db`                 | ✅ `PKI.UpdateDB()`                 |
| `set-pass [name]`           | ✅ `PKI.SetPass(name, old, new)`    |
| `init-pki`                  | via `NewWithFS()` (auto-creates dirs)|

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

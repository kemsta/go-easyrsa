# easy-rsa Command Parity

This document tracks the correspondence between easy-rsa commands and go-easyrsa library methods.

## Command → Method Mapping

| easy-rsa command            | Status in v1              | Go method (v2 target)               |
|-----------------------------|---------------------------|-------------------------------------|
| `init-pki`                  | `InitPKI()`               | `PKI.Init()`                        |
| `build-ca`                  | `NewCa()`                 | `PKI.BuildCA()`                     |
| `renew-ca`                  | —                         | `PKI.RenewCA()`                     |
| `gen-req [name]`            | —                         | `PKI.GenReq(name, opts)`            |
| `import-req`                | —                         | `PKI.ImportReq(name, csrPEM)`       |
| `sign-req [type] [name]`    | —                         | `PKI.SignReq(name, type, opts)`     |
| `build-client-full`         | `NewCert()`               | `PKI.BuildClientFull(name, opts)`   |
| `build-server-full`         | `NewCert()` + `Server()`  | `PKI.BuildServerFull(name, opts)`   |
| `build-serverClient-full`   | —                         | `PKI.BuildServerClientFull()`       |
| `expire [name]`             | —                         | `PKI.ExpireCert(name)`              |
| `renew [name]`              | —                         | `PKI.Renew(name, opts)`             |
| `revoke-issued [name]`      | `RevokeAllByCN()`         | `PKI.Revoke(name, reason)`          |
| `revoke-expired [name]`     | —                         | `PKI.RevokeExpired(name, reason)`   |
| `gen-crl`                   | embedded                  | `PKI.GenCRL()`                      |
| `show-cert [name]`          | —                         | `PKI.ShowCert(name)`                |
| `show-ca`                   | `GetLastCA()`             | `PKI.ShowCA()`                      |
| `show-crl`                  | `GetCRL()`                | `PKI.ShowCRL()`                     |
| `show-expire [days]`        | —                         | `PKI.ShowExpiring(days)`            |
| `show-revoke`               | —                         | `PKI.ShowRevoked()`                 |
| `verify-cert [name]`        | —                         | `PKI.VerifyCert(name)`              |
| `export-p12`                | —                         | `PKI.ExportP12(name, password)`     |
| `export-p7`                 | —                         | `PKI.ExportP7(name)`                |
| `export-p8`                 | —                         | `PKI.ExportP8(name, password)`      |
| `export-p1`                 | —                         | `PKI.ExportP1(name)`                |
| `gen-dh`                    | —                         | `PKI.GenDH(bits)`                   |
| `update-db`                 | —                         | `PKI.UpdateDB()`                    |
| `set-pass [name]`           | —                         | `PKI.SetPass(name, old, new)`       |

## Status Legend

- `—` — not implemented in v1
- Method name — implemented in v1 (possibly with different signature)
- `embedded` — functionality exists but is not exposed as a standalone method

## easy-rsa Reference

The easy-rsa binary is available as a git submodule at `subprojects/easy-rsa/`.
It is used as a reference implementation and for e2e testing.

```
subprojects/easy-rsa/easyrsa3/easyrsa --help
```

See `docs/design.md` for the v2 library architecture.

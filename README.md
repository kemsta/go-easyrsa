# 🔐 go-easyrsa

[![Build Status](https://github.com/kemsta/go-easyrsa/actions/workflows/test.yml/badge.svg)](https://github.com/kemsta/go-easyrsa/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/kemsta/go-easyrsa/badge.svg?branch=master)](https://coveralls.io/github/kemsta/go-easyrsa?branch=master)
[![GoDoc](https://pkg.go.dev/badge/github.com/kemsta/go-easyrsa/v2.svg)](https://pkg.go.dev/github.com/kemsta/go-easyrsa/v2)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Go library for [Easy-RSA](https://github.com/OpenVPN/easy-rsa)-compatible PKI operations, without shell scripts or `openssl` subprocesses.

The library currently provides typed equivalents for these core operations:

| easy-rsa command | go-easyrsa method |
|---|---|
| `init-pki` | `InitPKI(pki.InitPKIOptions{...})` |
| `build-ca` | `BuildCA()` |
| `gen-req` | `GenReq(name)` |
| `sign-req` | `SignReq(name, certType)` |
| `build-client-full` | `BuildClientFull(name)` |
| `build-server-full` | `BuildServerFull(name)` |
| `build-serverClient-full` | `BuildServerClientFull(name)` |
| `import-req` | `ImportReq(name, csrPEM)` |
| `renew` | `Renew(name)` / `RenewCA()` |
| `revoke` / `revoke-issued` | `Revoke(name, reason)` / `RevokeIssued(name, reason)` |
| `revoke-expired` | `RevokeExpired(name, reason)` |
| `revoke-renewed` | `RevokeRenewed(name, reason)` |
| `gen-crl` | `GenCRL()` |
| `gen-dh` | `GenDH(bits)` |
| `show-req` | `ShowReq(name)` and `CSR.Info()` |
| `show-cert` / `show-ca` | `ShowCert(name)` / `ShowCA()` |
| `show-eku` | `ShowEKU(nameOrPath)` |
| `show-crl` | `ShowCRL()` |
| `show-expire` | `ShowExpiring(days)` |
| `show-revoke` | `ShowRevoked()` |
| `show-renew` | `ShowRenewed()` |
| `verify-cert` | `VerifyCert(name)` |
| `update-db` | `UpdateDB()` |
| `expire` | `Expire(name)` |
| `export-p12` | `ExportP12(name, options)` |
| `export-p7` | `ExportP7(name, options)` |
| `export-p8` | `ExportP8(name, password)` |
| `export-p1` | `ExportP1(name, password)` |
| `set-pass` | `SetPass(name, oldPass, newPass)` |
| `serial` / `check-serial` | `Serial(serial)` / `CheckSerial(serial)` |
| `display-dn` | `DisplayDN(form, path)` |
| `rand` | `Rand(count, writer)` |

The filesystem backend follows the current Easy-RSA PKI layout for the operations covered by the interoperability tests.

For legacy v1 filesystem layout support, see [docs/legacy.md](docs/legacy.md).

---

## ✨ Features

- **Core Easy-RSA operations** - typed Go methods for CA, certificate, CRL, inspection, and export workflows
- **Tested interoperability** - open and create Easy-RSA/OpenSSL PKIs for the currently covered workflows
- **Key algorithms** - RSA (2048/3072/4096), ECDSA (P-256/P-384/P-521), Ed25519
- **Key encryption** - OpenSSL-compatible PBES2/PKCS#8 using AES-256-CBC and PBKDF2-HMAC-SHA256 (100,000 iterations), with legacy encrypted PEM read compatibility
- **Export formats** - PKCS#12, PKCS#7, PKCS#8, PKCS#1, Diffie-Hellman parameters
- **Pluggable transactional storage** - one `storage.Backend` coordinates independently testable key, CSR, index, serial, CRL, artifact, and lifecycle facets
- **Transactional mutations** - filesystem and memory backends lock, commit, and roll back complete PKI operations; durable filesystem journals recover interrupted commits
- **Orphan cleanup** - `Clean()` removes cert/key files not tracked by the index

---

## 🚀 Getting Started

### Installation

```bash
go get github.com/kemsta/go-easyrsa/v2@latest
```

### Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/kemsta/go-easyrsa/v2/pki"
)

func main() {
    // Optionally overlay EASYRSA_* environment variables onto a base config.
    cfg := pki.LoadConfigFromEnv(pki.Config{NoPass: true})

    // Create a filesystem-backed PKI (easy-rsa compatible layout)
    p, err := pki.NewWithFS("/path/to/pki", cfg)
    if err != nil {
        log.Fatal(err)
    }

    // Build a CA
    ca, err := p.BuildCA()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("CA created: %s\n", ca.Name)

    // Issue a server certificate
    server, err := p.BuildServerFull("vpn-server")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Server cert issued: %s\n", server.Name)

    // Issue a client certificate
    client, err := p.BuildClientFull("alice")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Client cert issued: %s\n", client.Name)

    // Generate CRL
    _, err = p.GenCRL()
    if err != nil {
        log.Fatal(err)
    }
}
```

---

## 💻 CLI

A Cobra-based `go-easyrsa` CLI is available as a separate module at:

```text
cmd/go-easyrsa
```

Install the latest release:

```bash
go install github.com/kemsta/go-easyrsa/cmd/go-easyrsa@latest
```

To build the current checkout instead:

```bash
cd cmd/go-easyrsa
go build
```

The CLI exposes a 36-command core subset whose positive compatibility is
verified against the pinned Easy-RSA v3.2.6 reference in CI. See
`docs/go-easyrsa-cli-parity.md` for the verified surface and the eight deferred
upstream commands; this is not a claim of complete upstream CLI parity.

PKCS#12 `friendlyName` customization (`--usefn`, `nofn`,
`EASYRSA_P12_FR_NAME`) and raw CA password input are not implemented and are
rejected explicitly. Generic unsupported result-affecting environment controls
can be ignored during migration with `GO_EASYRSA_STRICT_ENV_PARITY=0`; that
switch does not enable explicitly unsupported features.

Configuration precedence is:

```text
flags/args > EASYRSA_* env > base Config > library defaults
```

---

## 📖 Usage

### 🏗 CA Management

```go
// Build a new CA with custom settings
ca, err := p.BuildCA(
    pki.WithKeyAlgo(pki.KeyAlgoECDSA),
    pki.WithCN("My Root CA"),
    pki.WithDays(3650),
)

// Renew an existing CA (preserves the private key)
renewed, err := p.RenewCA()

// Inspect the CA
ca, err := p.ShowCA()
cert, _ := ca.Certificate()
fmt.Printf("Subject: %s\nExpires: %s\n", cert.Subject, cert.NotAfter)
```

### 📜 Certificate Issuance

```go
// Server cert with SANs
server, err := p.BuildServerFull("web",
    pki.WithDNSNames("example.com", "*.example.com"),
    pki.WithIPAddresses(net.ParseIP("10.0.0.1")),
)

// Client cert with passphrase-protected key
client, err := p.BuildClientFull("bob",
    pki.WithPassphrase("secret"),
)

// Dual-purpose server+client cert
dual, err := p.BuildServerClientFull("node-1")
```

### 📝 CSR Workflow

```go
// Generate a key + CSR (key stored, CSR returned)
csrPEM, err := p.GenReq("device-42")

// ... or import an externally created CSR
err = p.ImportReq("partner", externalCSRPEM)

// Sign the CSR
pair, err := p.SignReq("device-42", cert.CertTypeClient)
```

### 🔄 Renewal & Expiration

```go
// Renew a certificate (new cert, same key)
renewed, err := p.Renew("alice")

// Inspect the old, unrevoked renewal archive.
renewals, err := p.ShowRenewed()

// Revoke the old certificate after deploying its replacement.
// CRL generation remains a separate operation.
err = p.RevokeRenewed("alice", cert.ReasonSuperseded)

// Find certificates expiring within 30 days
expiring, err := p.ShowExpiring(30)

// Mark expired certs in the index
err = p.UpdateDB()
```

`ShowRenewed` returns `[]pki.RenewalInfo` with the storage name, serial,
actual-expiry `V`/`E` status, expiry time, common name, certificate PEM, and a
`RequiresRewind` marker for historical serial-based archives. `RevokeRenewed`
preserves the replacement certificate, private key, and CSR.

### ❌ Revocation

```go
// Revoke by name
err = p.Revoke("alice", cert.ReasonKeyCompromise)

// Revoke by serial number
err = p.RevokeBySerial(serial, cert.ReasonSuperseded)

// Revocation and CRL publication are separate Easy-RSA operations.
crlPEM, err := p.GenCRL()

// Check if a certificate is revoked
revoked, err := p.IsRevoked(serial)
```

### 📦 Export

```go
// PKCS#12 bundle (for browsers, Windows)
p12, err := p.ExportP12("alice", pki.ExportP12Options{Password: "export-password"})

// PKCS#7 certificate chain (no private key)
p7, err := p.ExportP7("alice", pki.ExportP7Options{})

// PKCS#8 private key
p8, err := p.ExportP8("alice", "key-password")

// Diffie-Hellman parameters
dh, err := p.GenDH(2048)
```

### 🔌 Custom Storage

```go
import "github.com/kemsta/go-easyrsa/v2/storage/memory"

// In-memory backend - ideal for tests
backend := memory.NewBackend()
p, err := pki.New(pki.Config{NoPass: true}, backend)
if err != nil {
    log.Fatal(err)
}
```

`pki.New` now accepts one aggregate `storage.Backend`; callers using the former
five-component constructor must wrap or migrate their storage implementation.
`storage/fs` and `storage/memory` implement the full writable contract.
`storage/legacy` is read-only and returns `storage.ErrReadOnly` for mutations.
`OpenWithFS` never creates a layout, while `NewWithFS` only ensures missing
layout directories and never resets an existing PKI.

---

## ⚙️ Configuration

Library code can explicitly overlay supported `EASYRSA_*` environment variables
onto a base config:

```go
cfg := pki.LoadConfigFromEnv(pki.Config{
    NoPass: true,
})
```

Supported config-backed environment variables include:

- `EASYRSA_ALGO`
- `EASYRSA_KEY_SIZE`
- `EASYRSA_CURVE`
- `EASYRSA_CA_EXPIRE`
- `EASYRSA_CERT_EXPIRE`
- `EASYRSA_CRL_DAYS`
- `EASYRSA_PRE_EXPIRY_WINDOW`
- `EASYRSA_DN`
- `EASYRSA_REQ_COUNTRY`
- `EASYRSA_REQ_PROVINCE`
- `EASYRSA_REQ_CITY`
- `EASYRSA_REQ_ORG`
- `EASYRSA_REQ_EMAIL`
- `EASYRSA_REQ_OU`
- `EASYRSA_NO_PASS`
- `EASYRSA_PASSIN`
- `EASYRSA_RAND_SN`

Then the resulting `Config` is still passed through normal library defaults by
`New(...)` / `NewWithFS(...)`.

```go
pki.Config{
    // Key generation defaults
    KeyAlgo:  pki.KeyAlgoRSA,   // rsa | ecdsa | ed25519
    KeySize:  2048,             // RSA key size
    Curve:    elliptic.P256(),  // ECDSA curve

    // Certificate validity
    DefaultDays:   825,         // End-entity certificates
    CADays:        3650,        // CA certificate
    CRLDays:       180,         // CRL validity
    PreExpiryDays: 90,          // ShowExpiring window

    // Subject DN
    DNMode:       pki.DNModeCNOnly, // cn_only | org
    SubjTemplate: pkix.Name{       // Template for org mode
        Organization: []string{"My Org"},
        Country:      []string{"US"},
    },

    // Key protection
    NoPass:        false,       // true = store keys unencrypted
    CAPassphrase:  "",          // CA key passphrase
    KeyPassphrase: "",          // Default key passphrase

    // Serial numbers
    SequentialSerial: false,    // false = random 128-bit (default)

    // Storage
    CAName: "ca",               // CA entity name in storage
}
```

---

## 📄 License

[MIT](LICENSE)

# 🔐 go-easyrsa

[![Build Status](https://github.com/kemsta/go-easyrsa/actions/workflows/test.yml/badge.svg)](https://github.com/kemsta/go-easyrsa/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/kemsta/go-easyrsa/badge.svg?branch=master)](https://coveralls.io/github/kemsta/go-easyrsa?branch=master)
[![GoDoc](https://pkg.go.dev/badge/github.com/kemsta/go-easyrsa.svg)](https://pkg.go.dev/github.com/kemsta/go-easyrsa)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A drop-in replacement for [easy-rsa](https://github.com/OpenVPN/easy-rsa) as a Go library - no shell scripts, no `openssl` subprocess, same PKI directory layout.

Every `easyrsa` command has a direct Go equivalent:

| easy-rsa command | go-easyrsa method |
|---|---|
| `init-pki` | `pki.NewWithFS(dir, cfg)` |
| `build-ca` | `BuildCA()` |
| `gen-req` | `GenReq(name)` |
| `sign-req` | `SignReq(name, certType)` |
| `build-client-full` | `BuildClientFull(name)` |
| `build-server-full` | `BuildServerFull(name)` |
| `build-serverClient-full` | `BuildServerClientFull(name)` |
| `import-req` | `ImportReq(name, csrPEM)` |
| `renew` | `Renew(name)` / `RenewCA()` |
| `revoke` | `Revoke(name, reason)` |
| `revoke-expired` | `RevokeExpired(name, reason)` |
| `gen-crl` | `GenCRL()` |
| `gen-dh` | `GenDH(bits)` |
| `show-cert` / `show-ca` | `ShowCert(name)` / `ShowCA()` |
| `show-crl` | `ShowCRL()` |
| `show-expired` | `ShowExpiring(days)` |
| `show-revoked` | `ShowRevoked()` |
| `verify-cert` | `VerifyCert(name)` |
| `update-db` | `UpdateDB()` |
| `expire-cert` | `ExpireCert(name)` |
| `export-p12` | `ExportP12(name, password)` |
| `export-p7` | `ExportP7(name)` |
| `export-p8` | `ExportP8(name, password)` |
| `export-p1` | `ExportP1(name)` |
| `set-pass` | `SetPass(name, oldPass, newPass)` |

The filesystem backend reads and writes the same `index.txt`, `serial`, `private/`, `issued/`, `certs_by_serial/` layout - you can point it at an existing easy-rsa PKI directory and it just works.

Compatibility with the legacy v1 filesystem layout is available via a separate **read-only** backend (`pki.NewWithLegacyFSRO(dir, cfg)`). See [docs/legacy.md](docs/legacy.md) for supported operations, limitations, and migration guidance.

---

## ✨ Features

- **Complete easy-rsa parity** - every shell command available as a typed Go method
- **Full interoperability** - open an existing easy-rsa/OpenSSL PKI, or create a new one that easy-rsa can read
- **Key algorithms** - RSA (2048/3072/4096), ECDSA (P-256/P-384/P-521), Ed25519
- **Key encryption** - AES-256-CBC passphrase protection for private keys
- **Export formats** - PKCS#12, PKCS#7, PKCS#8, PKCS#1, Diffie-Hellman parameters
- **Pluggable storage** - 5 clean interfaces (`KeyStorage`, `CSRStorage`, `IndexDB`, `SerialProvider`, `CRLHolder`); bring your own backend (database, S3, vault) or use the built-in filesystem/in-memory implementations
- **Crash-safe writes** - atomic file operations (temp → fsync → rename) for index and CRL
- **Orphan cleanup** - `Clean()` removes cert/key files not tracked by the index

---

## 🚀 Getting Started

### Installation

```bash
go get github.com/kemsta/go-easyrsa@latest
```

### Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/kemsta/go-easyrsa/pki"
)

func main() {
    // Create a filesystem-backed PKI (easy-rsa compatible layout)
    p, err := pki.NewWithFS("/path/to/pki", pki.Config{NoPass: true})
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

// Find certificates expiring within 30 days
expiring, err := p.ShowExpiring(30)

// Mark expired certs in the index
err = p.UpdateDB()
```

### ❌ Revocation

```go
// Revoke by name
err = p.Revoke("alice", cert.ReasonKeyCompromise)

// Revoke by serial number
err = p.RevokeBySerial(serial, cert.ReasonSuperseded)

// Regenerate CRL after revocation (automatic in Revoke*)
crlPEM, err := p.GenCRL()

// Check if a certificate is revoked
revoked, err := p.IsRevoked(serial)
```

### 📦 Export

```go
// PKCS#12 bundle (for browsers, Windows)
p12, err := p.ExportP12("alice", "export-password")

// PKCS#7 certificate chain (no private key)
p7, err := p.ExportP7("alice")

// PKCS#8 private key
p8, err := p.ExportP8("alice", "key-password")

// Diffie-Hellman parameters
dh, err := p.GenDH(2048)
```

### 🔌 Custom Storage

```go
import "github.com/kemsta/go-easyrsa/storage/memory"

// In-memory backend - ideal for tests
ks, csr, idx, sp, crl := memory.New()
p := pki.New(pki.Config{NoPass: true}, ks, csr, idx, sp, crl)
```

---

## ⚙️ Configuration

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

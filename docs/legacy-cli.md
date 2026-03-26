# Legacy compatibility CLI

`go-easyrsa` includes a small compatibility CLI for users coming from the old v1 command set.

The CLI lives in a separate Cobra-based submodule:

```text
cmd/go-easyrsa-legacy-cli
```

Build it from that directory:

```bash
cd cmd/go-easyrsa-legacy-cli
go build
```

## Supported commands

The command surface intentionally mirrors the tiny v1 CLI:

- `build-ca`
- `build-server-key <cn>`
- `build-key <cn>`
- `revoke-full <cn>`

Supported flags:

- global `--key-dir, -k`
- `build-server-key --dns, -n`
- `build-server-key --ip, -i`

## Compatibility model

This CLI is built on top of the current `pki.NewWithFS(...)` backend, so it writes the **current easy-rsa-compatible filesystem layout**, not the legacy v1 on-disk layout.

If the target directory already contains data, it must either be empty or already look like the current filesystem layout. Any other non-empty directory is rejected.

Its job is to preserve the old **command UX** and approximate the old v1 certificate defaults as closely as practical:

- plaintext keys by default (`NoPass`)
- RSA-2048 defaults
- long validity windows similar to v1
- server/client certificate profiles adjusted toward v1 semantics

## Example

```bash
go-easyrsa-legacy-cli -k ./keys build-ca
go-easyrsa-legacy-cli -k ./keys build-server-key vpn --dns vpn.example.test --ip 127.0.0.1
go-easyrsa-legacy-cli -k ./keys build-key alice
go-easyrsa-legacy-cli -k ./keys revoke-full alice
```

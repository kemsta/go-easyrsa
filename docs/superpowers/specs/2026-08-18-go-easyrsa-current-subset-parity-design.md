# go-easyrsa Current-Subset Parity Repair Design

**Status:** Approved; implementation order amended

**Date:** 2026-08-18

## Purpose

Repair the currently implemented `cmd/go-easyrsa` command subset after the dependency-only baseline commit `7a2e67d`. The repaired CLI must provide positive compatibility with Easy-RSA v3.2.6: every upstream-valid invocation inside the declared subset must also succeed in `go-easyrsa` and produce usable, interoperable results.

Exact rejection behavior is not a goal. `go-easyrsa` may accept additional forms, such as Cobra's `--flag value`, provided that every upstream form also works.

## Scope

### Included

The 28 command names already registered by `cmd/go-easyrsa`:

- `init-pki`
- `build-ca`
- `renew-ca`
- `gen-req`
- `import-req`
- `sign-req`
- `build-client-full`
- `build-server-full`
- `build-serverClient-full`
- `expire`
- `renew`
- `revoke`
- `revoke-issued`
- `revoke-expired`
- `gen-crl`
- `show-cert`
- `show-ca`
- `show-crl`
- `show-expire`
- `show-revoke`
- `verify-cert`
- `export-p12`
- `export-p7`
- `export-p8`
- `export-p1`
- `gen-dh`
- `update-db`
- `set-pass`

The phase also includes only flags, positional options, and result-affecting `EASYRSA_*` variables currently declared supported in `docs/go-easyrsa-cli-parity.md`. The matrix must be corrected wherever tests disprove an existing support claim.

### Excluded

This phase does not add the 16 upstream command names that are currently absent:

- `self-sign-server`, `self-sign-client`
- `inline`
- `revoke-renewed`
- `show-req`, `show-renew`, `show-eku`
- `import-ca`, `import-tls-key`
- `gen-tls-auth-key`, `gen-tls-crypt-key`
- `write`
- `serial`, `check-serial`
- `display-dn`
- `rand`

Flags and environment variables already marked unsupported or intentionally out of scope remain excluded, including `rawca`, `text`, `nofn`, friendly-name customization, digest selection, critical-extension controls, Netscape extensions, and operational shell/OpenSSL controls.

Dependency manifests and GitHub Actions version pins were updated first in `7a2e67d`. A new direct dependency required to implement a parity fix may be introduced in a later parity commit, but it must be used by production code and documented.

## Compatibility Contract

For an upstream-valid invocation within scope:

1. The identical canonical upstream argument vector is passed to both binaries.
2. `go-easyrsa` exits successfully when Easy-RSA v3.2.6 exits successfully.
3. Required files are created at Easy-RSA-compatible PKI-relative paths.
4. Generated certificates, requests, CRLs, keys, and export bundles are parseable by standard tooling and usable by the other implementation.
5. Result-affecting flags and environment variables have upstream-equivalent semantics.
6. Additional accepted argument forms are permitted.

The contract does not require identical logs, prompts, error text, cryptographic bytes, serial numbers, or wall-clock timestamps.

## Test Invocation Design

Parity scenarios use Easy-RSA's canonical syntax directly, for example:

```text
--san=DNS:vpn.example.test
--days=5
--passout=pass:secret
```

The same immutable `[]string` is sent unchanged to both binaries. There is no upstream-only argument translator. This prevents the harness from concealing CLI syntax incompatibilities.

The runner removes inherited `EASYRSA_*`, `GO_EASYRSA_*`, and test-control variables before applying each scenario's explicit environment. It must not force `EASYRSA_NO_PASS` globally because that changes passphrase scenarios. With the `e2e` build tag enabled, a missing Easy-RSA reference executable is a test failure rather than a skip.

Boolean flags remain individual arguments. Repeated flags remain repeated canonical arguments, for example:

```text
--san=DNS:vpn.example.test --san=IP:127.0.0.1
```

Global options must precede the command because upstream Easy-RSA requires that ordering.

## Runner and Artifact Design

The E2E runner records stdout, stderr, exit status, and the PKI directory independently. It does not substitute stdout for a missing artifact.

For commands that create files, both implementations must be checked at the same upstream-compatible relative path:

- `gen-dh` -> `dh.pem`
- `gen-crl` -> `crl.pem`
- `export-p12 NAME` -> `private/NAME.p12`
- `export-p7 NAME` -> `issued/NAME.p7b`
- `export-p8 NAME` -> `private/NAME.p8`
- `export-p1 NAME` -> `private/NAME.p1`

If `go-easyrsa` currently writes an artifact only to stdout, that is a product gap and must be fixed rather than normalized in the test adapter. Extra stdout is acceptable as long as it does not corrupt machine-readable output and the required artifact exists.

## Semantic State Comparison

The parity suite compares stable semantics rather than byte identity:

- certificate subject and SAN fields;
- certificate role and public-key algorithm/size;
- current entity status and revocation state;
- key and certificate availability;
- CRL contents;
- requested validity duration within a bounded clock tolerance;
- export bundle composition and encryption properties;
- sequential-serial behavior without requiring identical literal serial values.

The comparator normalizes only representation differences that are not part of the compatibility contract:

- `nil` versus empty collections;
- nondeterministic serial values;
- wall-clock creation offsets;
- implementation-internal CA bookkeeping that does not prevent Easy-RSA interoperability.

It must not normalize missing files, missing keys, subject differences, status differences, SAN differences, encryption differences, or export composition.

Logical entity identity must not be inferred solely from certificate CN. The loader must preserve filename base, certificate subject, index serial, and key path separately so `EASYRSA_REQ_CN` and `EASYRSA_NEW_SUBJECT` scenarios are compared correctly.

## Interoperability Checks

State projection alone is insufficient. Representative cross-implementation tests must verify both directions where the command supports an existing PKI:

- Easy-RSA can inspect and continue operating on a PKI produced by `go-easyrsa`.
- `go-easyrsa` can inspect and continue operating on a PKI produced by Easy-RSA.
- Keys re-encrypted by `set-pass` can be consumed with the declared passphrase.
- P1, P7, P8, and P12 artifacts can be decoded independently of their producer.

Standard encrypted PKCS#8 emitted by OpenSSL must be accepted. Legacy encrypted PEM already accepted by the library must remain readable.

## Known Repair Areas

The corrected harness has already isolated these categories:

1. **Test-only defects**
   - split `--flag value` syntax sent to upstream;
   - export, DH, and CRL data read from stdout instead of upstream files;
   - exact serial/time comparisons;
   - CA bookkeeping and `nil`/empty differences;
   - CN used incorrectly as the storage filename;
   - one flag-precedence scenario that is invalid in upstream because RSA is combined with an inherited EC curve.

2. **Product defects to resolve**
   - Easy-RSA-compatible default CA and organizational DN values;
   - subject email propagation;
   - renew and revoke lifecycle/file-layout semantics;
   - SAN environment-plus-flag accumulation;
   - `EASYRSA_REQ_SERIAL` semantics by DN mode;
   - OpenSSL-compatible encrypted PKCS#8 input and output;
   - `passin`, `passout`, and `set-pass` interoperability;
   - required file output for DH and export commands;
   - P1, P7, P8, and P12 encoding, composition, and password variants.

Each mismatch must first be reproduced as a focused failing test against Easy-RSA v3.2.6. The implementation changes only when the upstream-valid behavior is confirmed. Assertions must not be weakened merely to make the suite green.

## CI Design and Previous Blind Spot

GitHub CI did not observe these failures because `cmd/go-easyrsa/` and the workflow additions are uncommitted. The committed root `go test ./...` also stops at the nested `cmd/go-easyrsa/go.mod`, and the parity file is excluded unless the `e2e` build tag is enabled.

The parity repair adds mandatory steps with an explicit nested-module working directory:

```yaml
- name: Test go-easyrsa CLI
  working-directory: cmd/go-easyrsa
  run: go test -count=1 ./...

- name: Test go-easyrsa CLI E2E
  working-directory: cmd/go-easyrsa
  run: go test -tags=e2e -count=1 -timeout=10m ./...
```

The E2E job must check out the Easy-RSA submodule and run on an environment with OpenSSL available.

## Commit Boundary

The dependency-only commit precedes CLI source and E2E work:

```text
7a2e67d build: update project dependencies
```

The CLI baseline, trustworthy E2E harness, product fixes, CI activation, and corrected parity documentation may be split into multiple focused follow-up commits. Dependency version changes must not be repeated or mixed into those commits unless a new direct production dependency is required by a parity fix.

## Acceptance Criteria

- All in-scope scenarios pass against Easy-RSA v3.2.6 with identical canonical argument vectors.
- There is no baseline-failure allowlist or skipped known failure.
- Unit tests for the root module and `cmd/go-easyrsa` pass.
- `go test -tags=e2e -count=1 -timeout=10m ./...` passes from `cmd/go-easyrsa`.
- Required file artifacts exist at upstream-compatible paths and pass independent parsing checks.
- Representative cross-implementation PKI operations pass in both directions.
- Every one of the 28 registered command names is exercised by at least one canonical upstream-valid scenario.
- The support matrix distinguishes verified current-subset support from explicitly deferred upstream surface.
- The Easy-RSA submodule remains pinned to the verified v3.2.6 commit.
- The dependency update remains isolated in `7a2e67d`, and the repaired parity suite is green on top of it.

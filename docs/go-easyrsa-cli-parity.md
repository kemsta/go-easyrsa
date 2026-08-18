# go-easyrsa CLI compatibility matrix

This document tracks the dedicated CLI in `cmd/go-easyrsa` against Easy-RSA
v3.2.6.

## Compatibility target

The current phase targets **positive compatibility** for the existing command
subset: an invocation that succeeds in upstream Easy-RSA must also succeed in
`go-easyrsa` and produce usable, interoperable results.

Matching upstream rejection behavior, prompts, error wording, random serial
values, or exact timestamps is not required. `go-easyrsa` may accept additional
syntax, such as Cobra's `--flag value`, while parity scenarios use upstream's
canonical `--flag=value` form and place global options before the command.

## Status legend

- ✅ verified locally and by cross-implementation E2E
- 🟡 implemented with ordinary tests; cross-implementation verification pending
- ❌ intentionally unsupported in the current subset
- ⛔ outside the current result-compatibility scope

The tagged CLI E2E suite is currently being repaired. Therefore this document
does not mark the command subset as complete or drop-in compatible yet.

## Current command subset

These 28 registered command names are in scope. Registration and ordinary
coverage are present for the baseline, but command-by-command ordinary coverage
is still partial; each remains 🟡 until its canonical upstream scenario is
green.

| Command | Status |
|---|---:|
| `init-pki` | 🟡 |
| `build-ca` | 🟡 |
| `renew-ca` | 🟡 |
| `gen-req` | 🟡 |
| `import-req` | 🟡 |
| `sign-req` | 🟡 |
| `build-client-full` | 🟡 |
| `build-server-full` | 🟡 |
| `build-serverClient-full` | 🟡 |
| `expire` | 🟡 |
| `renew` | 🟡 |
| `revoke` | 🟡 |
| `revoke-issued` | 🟡 |
| `revoke-expired` | 🟡 |
| `gen-crl` | 🟡 |
| `show-cert` | 🟡 |
| `show-ca` | 🟡 |
| `show-crl` | 🟡 |
| `show-expire` | 🟡 |
| `show-revoke` | 🟡 |
| `verify-cert` | 🟡 |
| `export-p12` | 🟡 |
| `export-p7` | 🟡 |
| `export-p8` | 🟡 |
| `export-p1` | 🟡 |
| `gen-dh` | 🟡 |
| `update-db` | 🟡 |
| `set-pass` | 🟡 |

## Deferred upstream commands

These 16 upstream command names are not registered in the current phase:

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

## Flags and positional controls

### Implemented, parity pending

- PKI and validity: `--pki-dir`, `--days`, `--startdate`, `--enddate`
- key generation: `--algo`, `--keysize`, `--curve`
- request/signing: `--dn-mode`, `--req-cn`, `--req-c`, `--req-st`,
  `--req-city`, `--req-org`, `--req-email`, `--req-ou`, `--req-serial`
- extensions: `--san`, `--subject-alt-name`, `--auto-san`, `--copy-ext`,
  `--subca-len`, `--new-subject`
- key protection: `--nopass`, `--no-pass`, `--passin`, `--passout`
- compatibility: `--batch`
- positional controls used by the current subset: `nopass`, `subca`,
  `newsubj`, `preserve`, `legacy`, `noca`, `nokey`, `batch`, and `full`

`--san`, `--subject-alt-name`, and `EASYRSA_SAN` accumulate values. Output-key
operations require either `--passout`/`EASYRSA_PASSOUT` or an explicit
passwordless choice (`nopass`, `--nopass`, or `EASYRSA_NO_PASS=true`).
Passphrases loaded from the environment are not displayed as help defaults.

Commands now write artifacts at the upstream PKI-relative paths: `dh.pem`,
`crl.pem`, `private/NAME.p12`, `issued/NAME.p7b`, `private/NAME.p8`, and
`private/NAME.p1`. Binary artifacts are not substituted through stdout.
Private/public artifact modes are `0600`/`0644` on POSIX systems; Windows file
ACLs retain the platform defaults.

### Explicitly unsupported

- `rawca` / `EASYRSA_RAW_CA`
- request `text` output control
- `nofn`, `--usefn`, and `EASYRSA_P12_FR_NAME`
- digest selection
- critical BasicConstraints, KeyUsage, ExtendedKeyUsage, and SAN controls
- Netscape certificate/comment extensions
- arbitrary extra extensions

These controls are rejected rather than silently accepted. The strict-env
escape hatch does not enable explicitly unsupported command options.

## Result-affecting environment variables

The following variables are implemented in the current baseline but remain 🟡
until their upstream scenarios pass:

- location and crypto: `EASYRSA_PKI`, `EASYRSA_ALGO`, `EASYRSA_CURVE`,
  `EASYRSA_KEY_SIZE`
- validity: `EASYRSA_CA_EXPIRE`, `EASYRSA_CERT_EXPIRE`, `EASYRSA_CRL_DAYS`,
  `EASYRSA_PRE_EXPIRY_WINDOW`, `EASYRSA_START_DATE`, `EASYRSA_END_DATE`
- subject: `EASYRSA_DN`, `EASYRSA_REQ_CN`, `EASYRSA_REQ_COUNTRY`,
  `EASYRSA_REQ_PROVINCE`, `EASYRSA_REQ_CITY`, `EASYRSA_REQ_ORG`,
  `EASYRSA_REQ_EMAIL`, `EASYRSA_REQ_OU`, `EASYRSA_REQ_SERIAL`
- keys and serials: `EASYRSA_NO_PASS`, `EASYRSA_PASSIN`, `EASYRSA_PASSOUT`,
  `EASYRSA_RAND_SN`
- signing/extensions: `EASYRSA_SAN`, `EASYRSA_AUTO_SAN`, `EASYRSA_CP_EXT`,
  `EASYRSA_SUBCA_LEN`, `EASYRSA_NEW_SUBJECT`, `EASYRSA_PRESERVE_DN`
- execution: `EASYRSA_BATCH`

Malformed boolean values do not silently enable `EASYRSA_NO_PASS`. Invalid
numeric values are ignored by the non-failing library overlay and rejected by
the CLI before it creates or mutates a PKI. New encrypted private keys use
standard PBES2/PKCS#8 and legacy DEK-Info encrypted PEM remains readable.
Easy-RSA's default CA CN and organizational subject template are applied by the
CLI, including preservation of email attributes through CSR signing.

The following result-affecting variables are currently ❌:

- `EASYRSA_P12_FR_NAME`
- `EASYRSA_RAW_CA`
- `EASYRSA_DIGEST`
- `EASYRSA_BC_CRIT`, `EASYRSA_KU_CRIT`, `EASYRSA_EKU_CRIT`,
  `EASYRSA_SAN_CRIT`
- `EASYRSA_NS_SUPPORT`, `EASYRSA_NS_COMMENT`
- `EASYRSA_EXTRA_EXTS`
- `EASYRSA_ALIAS_DAYS`

Generic unsupported result-affecting environment requests are rejected by
default. `GO_EASYRSA_STRICT_ENV_PARITY=0` (or the legacy
`STRICT_ENV_PARITY=0`) allows those generic variables to be ignored during
migration. It does not bypass explicit `rawca` or PKCS#12 friendly-name
rejections.

## Operational controls outside this phase

Shell/OpenSSL plumbing and output-only controls remain ⛔, including variables
for debug/verbosity, temp directories, lock files, umask, vars-file loading,
OpenSSL/OpenVPN executable paths, custom OpenSSL configuration, inline files,
and shell error handling.

## Lifecycle compatibility

The CLI follows the upstream current-file lifecycle: `expire` moves a
certificate from `issued` to `expired`, while revoke commands archive current
certificate/key/request files under `revoked/*_by_serial`. Mutating CLI
commands share a sibling advisory `.<pki-name>.go-easyrsa.lock`; lifecycle
operations additionally pre-stage no-clobber copies and verify file identity
before source deletion or rollback. The library retains
its safer behavior of marking superseded renewal entries non-valid; semantic
parity treats that old-history status as an intentional internal difference
while requiring the current certificate and command continuation to match.

## Known E2E repair areas

The current failures are being separated into harness defects and product
defects. Work still required includes:

- identical canonical argv for both implementations;
- artifact verification at upstream PKI paths rather than stdout substitution;
- semantic comparison of entity identity, status, serial strategy, and time;
- cross-implementation verification of encrypted PKCS#8 and passphrase flows;
- cross-implementation verification of P1, P7, P8, P12, DH, and CRL composition;
- representative continuation of each implementation's PKI by the other.

A row moves to ✅ only after the corresponding upstream-valid scenario passes
without an expected-failure list or skipped known failure.

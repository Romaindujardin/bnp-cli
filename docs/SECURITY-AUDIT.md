# Security audit — bnp-sidecar 0.2.0

| Field | Value |
|---|---|
| Audit date | 2026-11-21 |
| Version | 0.2.0 |
| Scope | Original code, direct-mode client, tests, packaging, documentation and CI |
| Method | Manual code review, threat modeling, automated tests, static checks, dependency audit, packaging checks, secret-pattern scan and a live direct-mode read-only run |
| Live BNP validation | **Direct backend: yes** (November 2026). **Enable Banking backend: not performed in this repository.** |
| Overall result | No critical, high or medium issue identified in the reviewed scope. Residual risks are documented below. |

This audit covers the original code of `bnp-sidecar`, including the direct
BNP web client. It does not cover BNP Paribas, Enable Banking, `curl_cffi`,
`curl`, the browser, the operating system or the Python runtime.

## 1. Executive summary

The sidecar implements two read-only account-information backends:

1. **Enable Banking PSD2/AIS**: browser-based BNP login and SCA, a read-only
   PSD2 session, and account/balance/transaction reads.
2. **Direct BNP web session**: an interactive login against the current
   PingFederate page, manual 2FA, and the same read-only account endpoints used
   by the BNP web application.

The main security properties are:

1. **No credential persistence.** The Enable Banking backend never handles a
   BNP password. The direct backend asks for the customer ID and 6-digit code
   on the terminal for each run, converts the code to virtual-keyboard
   positions, and never writes it to disk, `argv`, an environment variable or a
   log. No direct cookie or 2FA state is persisted.
2. **No write endpoint exists.** Both backends have explicit read-only
   allowlists. There is no payment, transfer, order or generic HTTP passthrough.
3. **Secrets are separated and private.** The Enable Banking RSA key lives in
   its own `0600` file, never in `config.json`; the PSD2 session is a `0600`
   bearer-token file; the callback TLS key is `0600`.
4. **Sensitive files are handled defensively.** Reads use `O_NOFOLLOW`, reject
   non-regular files, reject group/other-readable modes and cap size. Writes
   are atomic, `0600`, `fsync`ed and symlink-refusing.
5. **Network destinations are constrained.** Enable Banking uses TLS, refuses
   redirects and pins the API host. Direct mode disables automatic redirects
   for data requests, validates every hop against a BNP host allowlist, and
   validates login/2FA form and link hosts before use.
6. **Secrets are redacted.** Credentials, application IDs, private-key lines,
   JWTs, authorization codes, `state` values, session IDs and direct-mode
   errors go through the redaction layer.
7. **The direct backend was validated live.** A November 2026 read-only run
   retrieved 6 accounts and 522 transactions with 0 per-account errors and no
   duplicate transaction identifiers.

The Enable Banking backend still lacks a live validation in this repository.
That is the main open item before claiming broad production readiness, but it
is a coverage limitation rather than a code defect.

## 2. Scope and method

Reviewed:

- `bnp_sidecar/*.py`;
- `bnp_sidecar/direct/*.py`;
- `tests/*.py`;
- `scripts/real_smoke.py`;
- `pyproject.toml`, `MANIFEST.in`, `.gitignore`;
- `README.md`, `SECURITY.md`, `docs/*.md`, `CHANGELOG.md`, `CONTRIBUTING.md`;
- `.github/workflows/ci.yml`.

Checks performed:

```bash
.venv/bin/pytest
uvx ruff check bnp_sidecar tests scripts
.venv/bin/python -m compileall -q bnp_sidecar tests scripts
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
uvx pip-audit --progress-spinner off
```

Manual searches:

- private-key blocks and PEM headers;
- password/OTP/SCA handling in both backends;
- direct-mode login, 2FA and cookie persistence;
- payment, transfer, order and write endpoints;
- local absolute paths and personal email addresses;
- IBAN-like strings and session/authorization identifiers;
- symlink and permission handling;
- subprocess, shell, `eval`, `exec` and dynamic import usage;
- logging of request URLs, headers and bodies;
- redirect handling and host allowlists.

The repository has no Git history yet (`.git` is absent), so no history scan was
possible. The scan covers the working tree that would be committed.

## 3. Findings

| ID | Severity | Status | Finding |
|---|---|---|---|
| AUD-01 | Informational | Open | Enable Banking mode has no live validation in this repository. It is tested against a fake API. The direct backend has been live-validated. |
| AUD-02 | Low (accepted) | Documented | The direct backend presents a Chrome-like TLS fingerprint through `curl_cffi` and does not execute JavaScript. It is not a browser and may fail when BNP changes its anti-bot challenge. |
| AUD-03 | Low (accepted) | Documented | The direct customer ID, 6-digit code and 2FA code exist in process memory while a command runs. A same-user attacker with memory access can observe them. This is outside the threat model. |
| AUD-04 | Info | Documented | Direct session cookies are kept in memory only and are never persisted or reused. Each command performs a new login. |
| AUD-05 | Low (accepted) | Documented | The Enable Banking private key and PSD2 session are plaintext files protected by `0600`, not by an OS keychain or application-level encryption. |
| AUD-06 | Low (accepted) | Documented | A process running as the same OS user can read the files, inspect memory, install a keylogger or modify the CLI. This is outside the threat model. |
| AUD-07 | Low (accepted) | Documented | The local HTTPS callback uses a self-signed certificate. The browser warning is expected; the certificate is not installed in the system trust store. |
| AUD-08 | Low (accepted) | Documented | No certificate pinning. Both backends rely on the system trust store and TLS verification. |
| AUD-09 | Low (accepted) | Documented | Exports are not encrypted by the sidecar. Users must protect the destination and avoid untrusted sync/backup targets. |
| AUD-10 | Low (accepted) | Documented | `data/mfa-structure.json` can contain page text (with digits masked). It contains no field value, code or cookie, but should still be treated as private and deleted when no longer needed. |
| AUD-11 | Low (accepted) | Documented | The direct backend depends on BNP's current web pages and endpoints. A bank-side change can break compatibility until the project is updated. The client fails explicitly rather than guessing. |
| AUD-12 | Low (accepted) | Documented | Two concurrent commands can race on `data/session.json` or `data/pending-link.json`. This can make a link fail or replace a session, but does not expose secrets. There is no lock file. Direct commands do not share session state. |
| AUD-13 | Info | Accepted | The Enable Banking application ID is stored in plaintext but is an identifier, not a secret. It is masked in user-facing summaries and redacted from errors. |
| AUD-14 | Info | Accepted | The authorization URL printed by `auth link` starts a consent flow. It is shown to the user and treated as sensitive, but it is not a reusable API credential. |
| AUD-15 | Info | Accepted | Enable Banking may expose only a subset of accounts for a given BNP profile. This is a provider coverage limitation, not a security issue. |

No critical, high or medium finding was identified. `AUD-01` is a release
coverage limitation, not a code defect.

## 4. Threat model

### Assets

- Enable Banking RSA private key;
- authorization codes and OAuth `state` values;
- PSD2 session identifiers;
- local callback TLS private key;
- direct-mode BNP customer ID and 6-digit code (transient);
- direct-mode 2FA codes (transient);
- direct-mode session cookies (transient);
- `data/mfa-structure.json` (redacted but potentially sensitive);
- account data and exports;
- availability and integrity of the local runtime state.

The BNP password and 2FA codes are **not persisted assets**. They exist only in
process memory while a direct command runs.

### Adversaries considered

| Adversary | In scope? | Mitigation / residual risk |
|---|---|---|
| Network attacker | Yes | TLS verification, redirect refusal/validation, host allowlists. No certificate pinning (AUD-08). |
| Malicious local user/process | Partly | `0600`/`0700`, `O_NOFOLLOW`, regular-file checks, atomic writes. Same-user compromise is out of scope (AUD-03/AUD-06). |
| Malicious website triggering the callback | Yes | Unpredictable 256-bit `state`, constant-time comparison, loopback-only bind, exact callback path. |
| Malicious callback URL or code | Yes | `state` validation, HTTPS authorization URL check, redaction, no code logging. |
| Accidental secret in output/log | Yes | Redaction layer, masked IDs, debug trace redaction, direct error redaction. |
| Malicious Enable Banking response | Partly | Defensive parsing, size cap, typed errors. The provider is trusted for account data. |
| Malicious BNP response / changed login page | Partly | Defensive parsing, host allowlists, explicit `UpstreamError` on unexpected structure. Compatibility is not guaranteed (AUD-11). |
| Compromised browser/extension | No | Out of scope; the user must review the authorization page. Direct mode does not use a browser. |
| Compromised BNP/Enable Banking | No | Out of scope. |
| Supply-chain attacker | Partly | Minimal runtime dependencies, `pip-audit`, pinned CI Ruff version, no install scripts. `curl_cffi` is optional and only installed for direct mode. |

### Trust boundaries

- local user account: trusted;
- other local users/processes: untrusted;
- network: untrusted;
- Enable Banking: trusted for PSD2 authorization and account data;
- BNP Paribas pages and APIs: trusted for login, SCA and account data, but
  responses are parsed defensively;
- browser: trusted to display the real page in Enable Banking mode, but not
  verifiable by the sidecar;
- `curl_cffi`/`curl`: trusted to perform TLS correctly, but redirect behavior
  is controlled by the sidecar.

## 5. Control verification

| Control | Implementation | Evidence |
|---|---|---|
| Enable Banking password boundary | No prompt, option, environment variable or storage field for a BNP password; browser-only authorization | Code search; `callback.py`; CLI help; README/SECURITY |
| Direct credential prompting | Customer ID with `input()`, 6-digit code with `getpass`; no CLI option or environment variable | `direct/cli.py`; `tests/test_direct_cli.py` |
| Direct password encoding | Digits converted to `gridPositions` indices; caller deletes the password reference | `direct/login.py`; `tests/test_direct_login.py` |
| Direct credential redaction | Customer ID and code registered with `Redactor`; messages and details redacted | `direct/cli.py`; `tests/test_direct_cli.py` |
| Direct session isolation | `curl_cffi.Session` in memory; no cookie file, no state file | `direct/client.py`; no persistence code path |
| Direct MFA structure | Structural fields only, digit-masked labels/text, values omitted; `0600` | `direct/login.py`; `private_files.py`; `tests/test_direct_login.py` |
| Direct redirect validation | `allow_redirects=False` for data reads; each hop checked against BNP hosts; final host checked | `direct/client.py`; `tests/test_direct_client.py` |
| Direct login/2FA host validation | Form action host, MFA form action host and MFA link host checked | `direct/login.py`; `direct/client.py`; tests |
| Read-only Enable Banking allowlist | Only `/application`, `/aspsps`, `/auth`, `/sessions`, `/accounts/*` reads and `DELETE /sessions/{id}` | `client.py`; no payment/transfer code path |
| Read-only direct allowlist | `_endpoint_allowed()` permits only 3 GET and 2 POST read endpoints | `direct/client.py`; `tests/test_direct_client.py` |
| JWT RS256 | `kid` = application ID, `iss` = `enablebanking.com`, `aud` = `api.enablebanking.com`, short TTL | `jwt.py`; `tests/test_jwt.py`; `tests/test_client.py` |
| Key separation | Private key in `config/private-key.pem`, never in `config.json` | `config.py`; `tests/test_config.py` |
| Consent cap | `min(180 days, bank maximum) - 60 s`, minimum 60 s | `client.maximum_consent_seconds`; `tests/test_client.py` |
| Private files | `0600`, atomic `fsync` + rename, symlink refusal, parent mode `0700` | `private_files.py`; `tests/test_private_files.py` |
| File reads | `O_NOFOLLOW`, regular-file check, group/other mode refusal, 64 KiB cap | `private_files.py`; tests |
| Session storage | `data/session.json` `0600`; session ID masked in summaries | `session.py`; `tests/test_session.py` |
| Pending link | 15-minute expiry, 256-bit state, constant-time compare | `session.py`; `tests/test_session.py` |
| Callback server | Loopback only, exact path, no URL logging, restrictive headers, CSP | `callback.py`; `tests/test_callback.py` |
| Local TLS | Self-signed cert in `cache/`, key `0600`, SAN localhost/127.0.0.1/::1, renewal | `callback.py`; `tests/test_callback.py` |
| Redirect URI validation | HTTPS, no credentials/fragment, loopback-only HTTP, bounded length, valid port | `config.py`; `tests/test_config.py` |
| Enable Banking base URL pinning | `https://api.enablebanking.com` only; loopback HTTP only for tests | `config.py`; `client.py`; tests |
| Enable Banking TLS/redirects | System TLS verification; 3xx refused | `client.py`; `tests/test_client.py` |
| Response bounds | 16 MiB maximum; 30 s default timeout, 1–120 s bound | `client.py`; `tests/test_client.py` |
| Redaction | Known secrets plus private-key, JWT, Bearer, `code`, `state` patterns | `redact.py`; `tests/test_redact.py`; CLI tests |
| Direct type normalization | Lowercase `type` values shared with Enable Banking | `direct/client.py`; `tests/test_direct_client.py` |
| Direct booked balance | `soldeComptable` preferred over `soldeDispo` | `direct/client.py`; `tests/test_direct_client.py` |
| Direct leap-day export | One-year default handled for 29 February | `direct/client.py`; `tests/test_direct_client.py` |
| Pagination safety (EB) | `continuation_key`, duplicate-key detection, page limit, truncation flag | `client.py`; `tests/test_client.py`; `tests/test_cli.py` |
| Amount safety | `Decimal` parsing; `DBIT` negative, `CRDT` positive | `serialize.py`; `direct/client.py`; tests |
| Partial export | Per-account errors, status `ok`/`partial`, no silent discard | `cli.py`; `direct/client.py`; tests |
| HOME sandbox (EB) | `HOME`/XDG redirected into the runtime directory | `paths.py`; CLI tests |
| Error model | Typed exceptions, stable codes and exit codes, JSON on stderr | `errors.py`; `tests/test_cli.py`; `tests/test_client.py` |
| Direct unexpected errors | Top-level catch, redaction, `INTERNAL_ERROR` JSON | `direct/cli.py`; tests |
| Export files | Atomic `0600`, symlink refusal | `cli.py`; `private_files.py`; `tests/test_cli.py` |

## 6. Test coverage

The automated suite contains **153 tests** and never contacts Enable Banking or
BNP Paribas.

| File | Tests | Focus |
|---|---:|---|
| `tests/test_callback.py` | 7 | Loopback server, state validation, denial, timeout, certificate |
| `tests/test_cli.py` | 21 | End-to-end Enable Banking CLI, auth, accounts, transactions, export, doctor, logout, redaction |
| `tests/test_client.py` | 18 | JWT header, `/auth` payload, pagination, redirects, error mapping, base URL |
| `tests/test_config.py` | 11 | Configuration round-trip, key separation, redirect rules, deletion |
| `tests/test_direct_cli.py` | 5 | `probe`, 2FA prompting, action filtering, error redaction |
| `tests/test_direct_client.py` | 26 | Account/transaction parsing, balances, history merge, redirect validation, allowlist, export edge cases |
| `tests/test_direct_login.py` | 15 | Login page parsing, keyboard positions, MFA detection, redacted structure |
| `tests/test_jwt.py` | 7 | RS256 header/payload, signature verification, key validation |
| `tests/test_private_files.py` | 11 | `0600`, parent mode, symlinks, modes, size cap, UTF-8 JSON |
| `tests/test_redact.py` | 8 | Private key, JWT, Bearer, `code`/`state`, nested values, IBAN |
| `tests/test_serialize.py` | 11 | Amounts, balances, account types, transaction signs, sorting, totals |
| `tests/test_session.py` | 13 | Session/pending-link persistence, expiry, account selection, deduplication |
| **Total** | **153** | |

The fake clients and fake HTTP server use synthetic identifiers and IBANs.
`scripts/real_smoke.py` is intentionally outside the automated suite.

## 7. Static, build and dependency results

| Check | Result |
|---|---|
| `pytest` | 153 passed |
| `ruff check bnp_sidecar tests scripts` | Clean |
| `compileall` | Clean |
| `python -m build` | Wheel and sdist built |
| `twine check dist/*` | Both passed |
| `pip-audit` | No known vulnerabilities in the installed environment at audit time |
| Secret-pattern scan | No real private key, session file, local absolute path or personal email found |
| Read-only search | No payment, transfer, order or generic write endpoint found |
| Packaging | `LICENSE`, `NOTICE`, `README.md`, `SECURITY.md`, docs, tests and scripts included; runtime data, PEM files and `dist/` ignored |

The core dependency set is intentionally small: `cryptography>=42` at runtime
and development-only test/build tools. `curl-cffi>=0.17` is optional (`direct`
extra) and is only imported by the direct backend. `urllib` handles Enable
Banking HTTP. There is no shell execution, `eval`, `exec`, dynamic import from
user input or subprocess call in the package.

## 8. Privacy and secret scan

The working tree contains:

- no Enable Banking application ID or private key from a real application;
- no BNP password, customer ID, 6-digit code, OTP, SCA code or session cookie;
- no real account holder name, IBAN, balance or transaction;
- no local absolute path or personal email address;
- only synthetic IBANs and identifiers in tests and documentation.

The live direct-mode run used a real account but its output was kept outside the
repository (`~/.local/share/bnp-sidecar/`). The documentation reports only
aggregate counts and a date range, not balances, labels or identifiers.

`tests/test_redact.py` builds a truncated, invalid PEM block at runtime to test
redaction. It is not a usable key and is not stored as a committed PEM file.
`.gitignore` excludes `config.json`, `private-key.pem`, `*.pem`, `*.key`,
`session.json`, `pending-link.json`, `mfa-structure.json`, `data/`, exports and
local environment files.

The repository is not yet initialized as a Git repository. Before publishing,
re-run a secret scan on the actual staged tree and on the Git history, and
verify that no runtime file was added by accident.

## 9. Residual risks

1. **Enable Banking live validation** (AUD-01). Bank-side consent behavior,
   account selection and callback compatibility remain unproven in this
   repository.
2. **Direct web compatibility** (AUD-02/AUD-11). BNP can change its login page,
   anti-bot challenge, field names or endpoints. The client fails explicitly.
3. **Transient credentials in memory** (AUD-03). Same-user memory access is out
   of scope.
4. **Plaintext Enable Banking secrets at rest** (AUD-05). The private key and
   session rely on file permissions, OS account separation and disk encryption.
5. **Same-user compromise** (AUD-06). A local attacker can read memory or
   modify the process.
6. **Self-signed callback** (AUD-07). Users must accept a localhost certificate
   warning. A user who ignores certificate warnings elsewhere is at greater
   risk.
7. **No certificate pinning** (AUD-08). A compromised CA or local trust store
   can intercept TLS.
8. **Unencrypted exports** (AUD-09). Backups and cloud sync may copy sensitive
   financial data.
9. **MFA structure file** (AUD-10). It contains no credentials but can contain
   page text. Delete it after diagnosis.
10. **Concurrent runs** (AUD-12). No lock file; avoid running `auth link` twice
    at the same time.
11. **Provider changes.** BNP Paribas or Enable Banking can change API fields,
    consent rules, SCA flows or anti-bot behavior. The sidecar fails explicitly
    rather than bypassing them.
12. **Browser trust** (Enable Banking). A compromised browser or extension can
    alter what the user sees or does during authorization.
13. **No background refresh.** Enable Banking consent expiry requires a new
    browser link; direct mode requires a new login for each command. Neither
    backend stores a BNP password to refresh silently.

## 10. Release checklist

- [x] Automated tests pass on Python 3.11–3.13.
- [x] Ruff, compileall, build and `twine check` pass.
- [x] `pip-audit` reports no known vulnerabilities.
- [x] Read-only endpoint allowlists reviewed for both backends.
- [x] Private-file and callback tests reviewed.
- [x] Direct live run performed: 6 accounts, 522 transactions, 0 per-account
      errors, 0 duplicate identifiers.
- [x] No real credentials or account data in the working tree.
- [ ] Run `scripts/real_smoke.py` with a real Enable Banking application and a
      real BNP Paribas account, then review the output for personal data before
      sharing.
- [ ] Re-run a secret scan on the staged Git tree and history after `git init`.
- [ ] Obtain explicit approval before publishing the repository.
- [ ] Rotate the Enable Banking application key if it was exposed during
      testing.

## 11. Conclusion

Within the reviewed scope, the implementation matches the intended security
model: a browser-only Enable Banking backend, an interactive direct backend
that never persists credentials or cookies, explicit read-only allowlists,
separated and private secret files, validated redirects, redacted diagnostics
and constrained network behavior.

The direct backend is suitable for read-only use after the November 2026 live
validation. The Enable Banking backend is suitable for a controlled real-account
smoke test once the user provides an Enable Banking application and registered
redirect URI. Neither backend should be described as universally
production-validated: bank-side changes remain a compatibility risk.

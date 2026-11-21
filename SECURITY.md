# Security policy

## Supported versions

| Version | Supported |
|---|---|
| `0.2.x` | Yes |
| `0.1.x` | No (superseded) |
| Older / forks | No |

Only the latest tagged release is supported. Security fixes are released as a
new patch version and documented in `CHANGELOG.md`.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private vulnerability reporting:

<https://github.com/Romaindujardin/bnp-sidecar/security/advisories/new>

Include, when possible:

- the affected version or commit;
- the backend used (`bnp-sidecar` / Enable Banking, or `bnp-direct`);
- the command and configuration used;
- a minimal reproduction;
- the impact you believe is possible;
- whether an Enable Banking application key, session, authorization code,
  IBAN, balance or transaction data was exposed.

**Never send your BNP customer ID, 6-digit code, 2FA code, cookies or a real
export.** Redact account identifiers and personal data from logs and
screenshots before sharing them.

You will receive an acknowledgement as soon as possible. Please allow time for
a fix and a coordinated release before publishing details.

## Scope

In scope:

- Enable Banking application ID and RSA private-key storage;
- PSD2 session, pending-link and callback-certificate storage;
- direct-mode credential prompting and in-memory handling;
- direct-mode login, 2FA parsing and virtual-keyboard encoding;
- direct-mode session cookies and redirect handling;
- the optional direct-mode `mfa-structure.json` file;
- secret leakage through stdout, stderr, logs, tracebacks or JSON errors;
- permission, symlink and atomic-write handling;
- authorization `state` validation and callback handling;
- argument handling and process-environment exposure;
- unsafe network usage in original code (TLS, redirects, base URL, host
  validation);
- vulnerabilities introduced by the original code of this repository.

Out of scope:

- vulnerabilities in BNP Paribas' website, applications, APIs, anti-bot
  protection or SCA infrastructure;
- vulnerabilities in Enable Banking's platform, API or authorization pages;
- vulnerabilities in `cryptography`, `curl_cffi`, `curl` or the Python standard
  library (report them upstream, then inform this project if the sidecar is
  affected);
- an attacker who already controls your user account, shell, keylogger, process
  memory or disk encryption;
- account takeover performed through BNP Paribas' or Enable Banking's own
  channels;
- the plaintext nature of the session file when filesystem permissions and disk
  encryption are working as intended (the PSD2 session is a bearer token and
  must be protected as one);
- financial loss caused by actions you perform outside this read-only tool;
- BNP Paribas changing its web pages, endpoints or anti-bot rules so that the
  direct backend stops working (this is a compatibility issue unless it leaks
  data or weakens a security control).

## Security model

### Two backends, two credential models

**Enable Banking (`bnp-sidecar`, `bnp-cli`).** The sidecar never asks for,
reads, stores, logs or transmits a BNP Paribas password or SCA code. BNP
performs login and strong customer authentication in the browser, on its own
pages. Enable Banking is the registered PSD2 third party and returns a
read-only session.

**Direct (`bnp-direct`).** The sidecar talks to the BNP web application with a
Chrome-like TLS fingerprint. It asks for the customer ID and 6-digit code on
the terminal for each run. The code is read with `getpass`, converted to
virtual-keyboard positions, and the original string is discarded by the caller
before the HTTP request is sent. The code is never:

- accepted as a command-line argument;
- read from an environment variable;
- written to a configuration or state file;
- reused between runs;
- included in a log, JSON output, error or traceback.

A 2FA code may be requested with `getpass` when BNP asks for one. Session
cookies and 2FA state stay in the `curl_cffi` process and are never persisted.
A new command performs a new login.

### Assets

- Enable Banking application ID (identifier) and RSA private key (secret);
- authorization codes and OAuth `state` values (single-use secrets);
- PSD2 session identifiers (bearer tokens);
- local callback TLS private key;
- direct-mode BNP customer ID and 6-digit code (transient, memory only);
- direct-mode 2FA codes (transient, memory only);
- direct-mode session cookies (transient, memory only);
- the redacted direct-mode `mfa-structure.json` file;
- account data: names, IBANs, balances, transactions, merchant labels and
  identifiers;
- exported JSON documents.

The BNP password and 2FA codes are **not persisted assets**. They exist only in
process memory while a direct command runs.

### Trust boundaries

- The local user account is trusted. Other local users and unprivileged
  processes are not.
- The network is untrusted. TLS certificate verification is mandatory for both
  backends.
- Enable Banking is trusted for the PSD2 session and account data it returns,
  but its responses are treated as untrusted input and parsed defensively.
- BNP Paribas' pages and APIs are trusted for authentication and account data,
  but their responses are treated as untrusted input and parsed defensively.
- The browser is trusted to display the real Enable Banking/BSP authorization
  page. The sidecar validates that the authorization URL returned by Enable
  Banking uses HTTPS and a hostname, but it cannot prove the page's
  authenticity.
- The direct backend trusts the BNP host allowlist and the TLS layer. It does
  not execute JavaScript, so it cannot verify a JavaScript challenge.

### Storage

| Path | Content | Mode |
|---|---|---|
| `~/.local/share/bnp-sidecar/` | runtime root | `0700` when created by the CLI |
| `config/config.json` | Enable Banking application ID, redirect URI, ASPSP settings | `0600` |
| `config/private-key.pem` | Enable Banking RSA private key | `0600` |
| `data/session.json` | PSD2 session and account identifiers | `0600` |
| `data/pending-link.json` | OAuth `state`, authorization ID, expiry | `0600` |
| `data/mfa-structure.json` | redacted direct-mode 2FA page structure | `0600` |
| `cache/callback-cert.pem` | local self-signed TLS certificate | `0600` |
| `cache/callback-key.pem` | local TLS private key | `0600` |
| `home/` | sandboxed `HOME`/XDG directories | `0700` |

The CLI only chmods directories it creates. A pre-existing directory keeps its
mode and is reported by `doctor` when group/other accessible. The direct CLI
also calls the private-path helper before writing `mfa-structure.json`, so a
new runtime root is created as `0700`.

The private key is **never** part of `config.json`. It is read from a separate
file or stdin and validated as an unencrypted RSA key of at least 2048 bits.
JWT tokens are signed in memory for each request and never persisted.

The PSD2 session file is a **plaintext bearer token**. It relies on `0600`, the
user's umask, disk encryption and OS account separation. There is no OS
keychain integration in 0.2.0.

`mfa-structure.json` contains only a structural description of a 2FA page:
hosts, paths, query parameter names, form field names and types, button labels,
link labels, script/iframe hosts and a digit-masked body excerpt. It never
contains a submitted value, code, password, cookie or authorization header.
Treat it as sensitive anyway: page text can contain personal or account
information. Delete it if it is not needed for diagnosis.

### Secrets in transit and in memory

- The Enable Banking private key can be passed as a file path or read from
  stdin with `--private-key-stdin`; its content is never accepted in `argv`.
- Authorization codes and `state` values are never accepted as positional
  arguments. `auth complete` accepts a callback URL, preferably on stdin with
  `--callback-url-stdin`, and redacts the code from errors.
- The authorization `state` is generated with 256 bits of entropy, stored for
  at most 15 minutes and compared with `secrets.compare_digest`.
- Session identifiers, application IDs and private-key lines are registered
  with the redaction layer. JWTs and `Authorization: Bearer` headers are also
  matched by generic patterns.
- The direct customer ID and 6-digit code are registered with the redaction
  layer for the duration of the command. Errors and structured details are
  redacted before being written to stderr.
- The direct 6-digit code is converted to keyboard positions; the original
  string is deleted by the caller. Python strings are immutable and may remain
  in process memory until garbage collection, so a same-user attacker with
  memory access can still observe them. This is outside the threat model.
- `--debug` adds a traceback, but the traceback is redacted before being
  written to stderr.

### Network

#### Enable Banking

The sidecar uses the Python standard library HTTP client with:

- TLS certificate verification enabled;
- HTTP redirects refused (a 3xx response is an error, never followed);
- a fixed base URL, `https://api.enablebanking.com`;
- an `http://` base URL only for a loopback test server, never for production;
- a 30-second default timeout, bounded between 1 and 120 seconds;
- a 16 MiB response-size limit;
- `Accept-Encoding: identity`, avoiding decompression bombs;
- no proxies configured by the sidecar itself.

Enable Banking API requests use a short-lived RS256 JWT with:

- `kid` = application ID;
- `iss` = `enablebanking.com`;
- `aud` = `api.enablebanking.com`;
- `iat` / `exp`, with a default lifetime of one hour.

The authorization URL returned by `POST /auth` is accepted only if it uses
HTTPS and contains a hostname. The local callback server binds only to
`localhost`, `127.0.0.1` or `::1`, on the exact path of the registered redirect
URI.

#### Direct

The direct backend uses `curl_cffi` with a Chrome TLS fingerprint because the
current BNP login page is protected by Akamai. It:

- verifies TLS through the normal `curl`/system trust store;
- disables automatic redirect following for data requests and validates each
  hop against an allowlist before sending the next request;
- accepts only BNP/Hello Bank hosts in that allowlist;
- validates the login form action host before submitting credentials;
- validates 2FA form actions and links before following them;
- sends only `GET` and `POST` requests to the read-only endpoints listed below;
- uses a 30-second timeout;
- never writes cookies to disk and never loads cookies from disk;
- never sends the customer ID or code to any host outside the BNP allowlist.

The login page itself is loaded from
`https://mabanque.bnpparibas/fr/connexion`. The form action must be on
`connexion.mabanque.bnpparibas` or `connexion.hellobank.fr`.

### Callback server (Enable Banking)

- Binds only to a loopback address;
- serves only the exact callback path;
- validates `state` before accepting a code or an error;
- never logs the request URL or query string;
- returns a minimal HTML page with `Cache-Control: no-store`, `nosniff`,
  `Referrer-Policy: no-referrer` and a restrictive Content Security Policy;
- uses a self-signed certificate generated locally for HTTPS callbacks. The
  browser warning is expected; accepting it only affects the localhost
  connection.

### Read-only design

Enable Banking endpoints implemented:

```text
GET    /application
GET    /aspsps
POST   /auth
POST   /sessions
GET    /sessions/{id}
DELETE /sessions/{id}
GET    /accounts/{uid}/details
GET    /accounts/{uid}/balances
GET    /accounts/{uid}/transactions
```

There is no payment-initiation endpoint, no transfer command, no order command
and no generic HTTP passthrough. `DELETE /sessions/{id}` only revokes the
session created by the sidecar.

Direct endpoints implemented:

```text
GET  /serviceinfosclient-wspl/rpc/InfosClient
GET  /udc-wspl/rest/getlstcpt
GET  /rib-wspl/rpc/comptes
POST /rop2-wspl/rest/releveOp
POST /rop-wspl/rest/releveOp   (legacy history fallback)
```

The `_endpoint_allowed()` allowlist rejects every other path and every other
HTTP method. There is no helper that accepts an arbitrary URL. Login and 2FA
requests are separate, host-validated requests to the BNP authentication
pages, not generic data requests.

### Dependencies

- Runtime dependency: `cryptography>=42`.
- Optional direct dependency: `curl-cffi>=0.17` (installed with the `direct`
  extra).
- Enable Banking HTTP is handled by `urllib` from the standard library.
- `pytest`, `build`, `twine` and coverage tools are development-only.
- CI runs the tests on Python 3.11, 3.12 and 3.13.
- For release work, run `pip-audit` in a fresh virtual environment and review
  dependency updates deliberately.
- Do not install this project from an untrusted fork.

### Known limitations

- A malicious process running as your user can read the Enable Banking private
  key and session files, inspect process memory while a command runs, install a
  keylogger or modify the CLI. File permissions cannot defeat a compromised
  session. This also applies to the transient direct-mode code and cookies.
- The Enable Banking private key and the PSD2 session are stored in plaintext
  files protected by `0600` and disk encryption. They are not encrypted by the
  sidecar.
- The direct backend reproduces BNP's web flow. BNP can change the login page,
  endpoints, field names or anti-bot behavior at any time. The sidecar fails
  explicitly rather than bypassing a control.
- The direct backend is not a browser and does not execute JavaScript. A page
  that requires a JavaScript challenge cannot be completed.
- The direct backend does not persist cookies. Each command performs a new
  login and may require a new 2FA confirmation.
- The local callback certificate is self-signed. A user who ignores browser
  certificate warnings on other sites weakens their own defense.
- The sidecar does not pin certificates, does not verify the authorization page
  contents and does not protect against a compromised browser or DNS.
- Enable Banking, BNP Paribas or a malicious browser extension could display a
  modified authorization page. Review the page and the requested accounts
  before approving.
- The optional `mfa-structure.json` file can contain page text. It is private
  (`0600`) but not encrypted.
- Exports are not encrypted. They may be synced by backup or cloud tools.
- PSD2 consent can be revoked at any time by BNP Paribas or the user. The
  sidecar treats a revoked session as expired and asks for a new link.
- Enable Banking mode has not been live-validated in this repository. The
  provider may expose only a subset of accounts for a given BNP profile.
- Direct mode was live-validated in November 2026, but bank-side behavior can
  change without notice. Automated tests cannot prove future compatibility.

### Hardening recommendations

- Enable full-disk encryption and a screen lock.
- Run the sidecar under your own dedicated OS account; do not share the runtime
  directory.
- Keep the runtime root at `0700` and private files at `0600`.
- Prefer `--private-key-stdin` if command history or process listing is a
  concern.
- Revoke sessions with `bnp-sidecar auth logout` when you no longer need them.
- Rotate the Enable Banking application key if the private key may have been
  exposed.
- Delete `data/mfa-structure.json` after diagnosing a 2FA page change.
- Store exports in an encrypted volume and delete them when no longer needed.
- Review the authorization page and the account selection at BNP Paribas before
  approving the consent.
- Prefer `bnp-direct export --output PATH` over shell redirection when
  exporting direct data, so the sidecar can enforce `0600`.

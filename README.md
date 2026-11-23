# BNP Paribas sidecar

[![CI](https://github.com/Romaindujardin/bnp-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/Romaindujardin/bnp-cli/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

An unofficial, **read-only** command-line client for BNP Paribas account
information. It exports accounts, balances and transactions as stable JSON and
offers two independent backends:

| Backend | Command | Authentication | Status |
|---|---|---|---|
| Enable Banking PSD2/AIS | `bnp-sidecar`, `bnp-cli` | Browser; BNP password never enters the sidecar | Tested against a fake API. Live coverage depends on the Enable Banking application. |
| Direct BNP web session | `bnp-direct` | Customer ID and 6-digit code typed in the terminal, plus BNP 2FA | Experimental. Live-validated in November 2026. |

> **Read-only.** Neither backend initiates a payment, transfer, order or any
> other write operation. Only account-information endpoints are implemented,
> behind explicit allowlists.
>
> **Unofficial.** This project is not affiliated with, endorsed by, or supported
> by BNP Paribas or Enable Banking Oy. Use it with your own account, at your own
> risk, and in accordance with both providers' terms of service.
>
> **Credentials.** The Enable Banking backend never asks for a BNP password:
> login and strong customer authentication happen in your browser. The direct
> backend asks for your customer ID and 6-digit code on the terminal for each
> run; the code is never written to disk, never placed in `argv`, never logged,
> and is cleared from memory after the login form is built. A 2FA code may also
> be requested interactively.

## Status

Version 0.2.0 adds the direct backend. The automated suite covers **153 tests**
on Python 3.11, 3.12 and 3.13 and never contacts Enable Banking or BNP Paribas.

Direct mode was validated against a live personal BNP Paribas account in
November 2026:

- 6 accounts returned: checking, two savings accounts, a Livret Jeune, a PEL and
  a personal loan;
- 522 transactions exported over a 13-month range;
- 0 per-account errors and 0 duplicate transaction identifiers.

That live run covered login, 2FA, the account list, balances and the
recent-history endpoint. The legacy-history fallback and the RIB-to-IBAN
enrichment added afterwards are covered by unit tests but had not been re-run
against a real account at publication time.

The Enable Banking backend is exercised against a local fake API, including JWT
signatures, pagination, error mapping, callback validation and file permissions.
It has not been validated with a live Enable Banking application in this
repository. In a live test on one BNP profile, Enable Banking exposed only the
checking account; the direct backend was added to read the same account list as
the BNP web application.

No credential, session, IBAN or transaction from a real account is present in
this repository. Account numbers in the examples are synthetic.

## Features

Common:

- JSON-only output on stdout; human diagnostics on stderr;
- accounts, balances, transactions and full export;
- read-only endpoint allowlists; no payment, transfer, order or generic write
  path;
- private files written atomically with mode `0600`; symlinks refused;
- redaction of credentials, session identifiers, authorization codes, JWTs and
  other secrets from errors and diagnostics;
- partial exports: one failing account does not discard the others;
- no BNP password or session persisted by the direct backend.

Enable Banking mode:

- RS256 JWT signed on the fly for every request;
- local HTTPS callback with a self-signed certificate generated on first use;
- PSD2 consent capped at 180 days, with a 60-second safety margin;
- pagination until no `continuation_key` remains, with duplicate-key and
  page-limit protection;
- booked balance from `CLBD`, available balance from `CLAV` / `ITAV` / `OPAV`;
- `doctor` command for Python, storage, configuration, key, session and network
  checks.

Direct mode:

- Chrome-like TLS fingerprint through `curl_cffi` for the current PingFederate
  login page;
- virtual-keyboard position encoding for the 6-digit code;
- interactive handling of SMS codes, app approval, forms and validation links;
- redirects validated hop by hop against an allowlist of BNP hosts;
- account list, balances and masked account numbers from the same endpoints as
  the BNP web application;
- transaction history merged from the current endpoint and the legacy endpoint,
  deduplicated by `idOperation`, with a three-year clamp;
- RIB-to-IBAN conversion with checksum validation when BNP exposes a RIB
  instead of an IBAN;
- normalized lowercase account types shared with the Enable Banking backend.

## How it works

### Enable Banking backend

```text
bnp-sidecar
    |
    +-- Enable Banking API (HTTPS, JWT RS256)
    |      POST /auth          -> authorization URL + authorization_id
    |      POST /sessions      -> PSD2 session + account list
    |      GET  /sessions/{id} -> accounts and identification hashes
    |      GET  /accounts/{uid}/details
    |      GET  /accounts/{uid}/balances
    |      GET  /accounts/{uid}/transactions
    |      DELETE /sessions/{id} (local logout)
    |
    +-- browser -> BNP Paribas login + SCA
    |
    +-- local callback -> authorization code -> PSD2 session
```

The Enable Banking application **is** the PSD2 third party. It holds the
application ID and RSA key, receives the authorization code, and returns a
session that grants read access to the accounts you approved at BNP Paribas.
The sidecar only talks to Enable Banking; it never talks to a BNP API directly
and never sees your BNP credentials.

### Direct backend

```text
bnp-direct
    |
    +-- GET  https://mabanque.bnpparibas/fr/connexion
    |      -> PingFederate form, virtual keyboard grid, ThreatMetrix token
    |
    +-- POST form action (customer ID + keyboard positions)
    |      -> authenticated session, or 2FA page
    |
    +-- interactive 2FA (SMS code, app approval, form or link)
    |
    +-- GET  /serviceinfosclient-wspl/rpc/InfosClient     session check
    +-- GET  /udc-wspl/rest/getlstcpt                    accounts + balances
    +-- GET  /rib-wspl/rpc/comptes                       RIBs / IBANs
    +-- POST /rop2-wspl/rest/releveOp                    recent transactions
    +-- POST /rop-wspl/rest/releveOp                     legacy history fallback
```

The direct backend reproduces the read-only requests that the BNP web
application performs. It is not an official BNP API. BNP can change its login
page, anti-bot protection, field names or endpoints at any time; the sidecar
fails explicitly rather than guessing.

The session lives only in the `curl_cffi` process. No cookie, password or 2FA
code is written to disk, and each command performs a new login. The optional
`data/mfa-structure.json` file contains a redacted structural description of a
2FA page (field names, button labels, hosts, paths, masked text), never a field
value, code or password.

## Requirements

- Python 3.11 or newer;
- macOS or Linux;
- network access to BNP Paribas, and to Enable Banking if that backend is used.

Enable Banking mode also requires:

- an Enable Banking account with an application and an RSA key pair;
- a redirect URI registered in the Enable Banking dashboard;
- a BNP Paribas account that Enable Banking can access in the selected country.

Direct mode also requires:

- the optional `curl-cffi` dependency (`pip install "bnp-sidecar[direct]"`);
- your BNP customer ID and 6-digit code;
- your usual 2FA device (SMS or BNP application).

Enable Banking's dashboard documents how to generate a key pair and register
the application. The public key or certificate is uploaded to Enable Banking;
the private key stays on your machine.

## Installation

### From source

```bash
git clone https://github.com/Romaindujardin/bnp-cli.git
cd bnp-cli
python3.11 -m venv .venv
.venv/bin/pip install --upgrade pip

# Enable Banking backend only
.venv/bin/pip install -e ".[dev]"

# Both backends
.venv/bin/pip install -e ".[dev,direct]"
```

The commands are then available as `.venv/bin/bnp-sidecar`,
`.venv/bin/bnp-cli` and `.venv/bin/bnp-direct`.

### With pipx

```bash
# Enable Banking backend
pipx install "git+https://github.com/Romaindujardin/bnp-cli.git"

# Add the direct backend
pipx inject bnp-cli curl-cffi
```

The project is not published on PyPI.

## Quick start: Enable Banking

```bash
# 1. Store the Enable Banking application ID and the RSA private key.
#    The key file must already be private (mode 0600).
bnp-sidecar auth setup \
  --application-id "your-enable-banking-application-id" \
  --private-key "$HOME/.config/enable-banking/private-key.pem" \
  --redirect-uri "https://localhost:8787/callback"

# 2. Open the authorization URL in a browser, authenticate at BNP Paribas,
#    and let the local callback create the PSD2 session.
bnp-sidecar auth link

# 3. Check the installation, the local files and the Enable Banking access.
bnp-sidecar doctor --network

# 4. Read accounts and balances.
bnp-sidecar accounts

# 5. Read transactions for a date range.
bnp-sidecar transactions --from 2026-11-01 --to 2026-11-30

# 6. Export everything into a private file (mode 0600).
bnp-sidecar export --output "$HOME/Documents/bnp-export.json"
```

If the private key must not appear in a shell command at all, read it from
stdin instead:

```bash
bnp-sidecar auth setup \
  --application-id "your-enable-banking-application-id" \
  --private-key-stdin \
  < "$HOME/.config/enable-banking/private-key.pem"
```

The application ID and the redirect URI are written to
`config/config.json`; the private key is written to a separate
`config/private-key.pem`. Both files are `0600`.

## Quick start: direct backend

```bash
# 1. Check that the login page is reachable and understood. No credentials.
bnp-direct probe

# 2. Read accounts and balances. The CLI prompts for the customer ID and code.
bnp-direct accounts --output "$HOME/Documents/bnp-accounts.json"

# 3. Export accounts and transactions.
bnp-direct export \
  --since 2025-01-01 \
  --output "$HOME/Documents/bnp-export.json"

# 4. Export one account only, without transactions.
bnp-direct export --account "Livret A" --no-transactions
```

The customer ID is read from the terminal. The 6-digit code is read with
`getpass`, so it is not echoed. The password is converted to virtual-keyboard
positions and the original string is discarded before the HTTP request is sent.
The password is never stored, never reused between runs and never accepted on
the command line.

`bnp-direct` writes its optional 2FA structure file under
`~/.local/share/bnp-sidecar/data/`. Set `BNP_SIDECAR_HOME` to use another
runtime root. The direct command has no `--data-dir` option.

### Direct mode 2FA

When BNP requests strong authentication, the CLI prints a short description and
offers the actions it recognizes:

- an SMS or numeric code field: the code is read with `getpass`;
- an app approval page: validate in the BNP application, then press Enter;
- a form or validation link: choose one of the numbered actions.

Use `a` on an approval page to display the available actions. The structural
description of the page is written to
`~/.local/share/bnp-sidecar/data/mfa-structure.json` (`0600`) to help diagnose
page changes. It contains no submitted value, code or password. Delete it if you
do not need it.

### Direct mode history and balances

- `releveOp` on `/rop2-wspl/` returns roughly the last year.
- For an older `--since`, the client also queries the legacy
  `/rop-wspl/rest/releveOp` endpoint and merges both histories by
  `idOperation`. The legacy range is clamped to three years.
- Identical transactions from the two endpoints are deduplicated; genuinely
  distinct transactions with the same label and amount are kept.
- The booked balance comes from `soldeComptable`; the available balance comes
  from `soldeDispo`. If one field is absent, the other is used as a fallback.
- Some accounts expose a French RIB instead of an IBAN. The client converts a
  21- or 23-digit RIB to an IBAN and verifies both checksums. If no valid IBAN
  can be built, `iban` is `null`; the BNP account key remains the stable
  identifier.

## Commands

### Enable Banking commands

| Command | Description |
|---|---|
| `auth setup` | Store the application ID, RSA key and redirect URI. |
| `auth link` | Start the browser authorization and create the PSD2 session. |
| `auth complete` | Exchange a callback URL for a session (manual/non-local callback). |
| `auth status` | Show configuration, session and pending-link state. |
| `auth logout` | Revoke the remote session and delete local session state. |
| `accounts` | List accounts with booked and available balances. |
| `transactions` | List transactions, with date/status filters and pagination. |
| `export` | Export accounts, balances and transactions in one document. |
| `doctor` | Diagnose Python, storage, configuration, key, session and network. |

Common Enable Banking options:

| Option | Description |
|---|---|
| `--data-dir PATH` | Runtime directory (default: `~/.local/share/bnp-sidecar`). |
| `--debug` | Add a redacted traceback to JSON errors. |
| `--version` | Print the version. |

`BNP_SIDECAR_HOME` is also accepted as the runtime directory when
`--data-dir` is not given.

### Direct commands

| Command | Description |
|---|---|
| `probe` | Load the BNP login page without credentials and report the form, grid and token presence. |
| `accounts` | Log in, read the account list and balances, and write the JSON document. |
| `export` | Log in, read accounts and transactions, and write the JSON document. |

Direct options:

| Option | Description |
|---|---|
| `--output PATH` | Write the JSON document atomically with mode `0600` instead of stdout. |
| `--raw` | Include raw BNP objects (personal data). |
| `--since YYYY-MM-DD` | Export start date (default: one year before `--until`). |
| `--until YYYY-MM-DD` | Export end date (default: today). |
| `--account SELECTOR` | Repeatable account filter: key, name, product or IBAN. |
| `--no-transactions` | Export accounts and balances only. |
| `--customer-id ID` | BNP customer number (7–10 digits); also `BNP_CUSTOMER_ID`. |
| `--password-stdin` | Read the six-digit secret from stdin. Never stored. |
| `--mfa-dir PATH` | Private directory (mode `0700`) used to exchange MFA requests/responses. |
| `--mfa-timeout SECONDS` | Maximum wait for an MFA response (default: `180`). |

Each direct command performs its own login. A BNP web session expires after
roughly 12–24 minutes of inactivity; there is no cookie persistence to reuse.

#### Non-interactive MFA broker

The `--mfa-dir` option is intended for a local dashboard or any automation. It
keeps the password out of argv and environment variables: the CLI reads it
once from stdin, uses it for the login, and never writes it to disk.

When BNP requests strong authentication, the CLI writes `mfa-request.json`
(mode `0600`) in the private directory and polls for `mfa-response.json`:

```json
{
  "schema": "bnp-sidecar/mfa-request/v1",
  "id": "…",
  "kind": "sms",
  "page": { "host": "mabanque.bnpparibas", "path": "/…", "queryKeys": [] },
  "codeRequired": true,
  "actions": [{ "index": 0, "label": "Valider (formulaire 1)", "kind": "form" }]
}
```

The request contains only the challenge type, the masked page location and the
allowed action labels. It never contains form field values, CSRF tokens or
cookies. Write the response atomically with the matching `id`:

```json
{ "schema": "bnp-sidecar/mfa-response/v1", "id": "…", "code": "123456" }
```

For an approval in the BNP mobile app, use `{ "id": "…", "action": 0 }`
(action `0` is “I approved in the BNP app”). For other challenges, send the
index of the desired action. The CLI deletes the request and response files
after use. On timeout it exits with `MFA_REQUIRED` without persisting anything.

Example:

```bash
install -d -m 700 /run/user/$(id -u)/bnp-mfa
printf '%s\n' "$BNP_SECRET" | bnp-direct export \
  --customer-id "$BNP_CUSTOMER_ID" \
  --password-stdin \
  --mfa-dir /run/user/$(id -u)/bnp-mfa \
  --output "$HOME/Documents/bnp-export.json"
```

### Selecting accounts (Enable Banking)

`--account` is repeatable and accepts an account UID, IBAN, identification
hash, exact name or exact product. Without a selector, commands process every
account in the session.

```bash
bnp-sidecar accounts --account "Compte de dépôt"
bnp-sidecar transactions --account "Livret A" --from 2026-01-01 --limit 50
bnp-sidecar export --account "PEA" --from 2026-01-01
```

An unknown selector fails with `USAGE_ERROR` (exit code 2). An ambiguous name
also fails and asks for the UID instead.

For direct mode, `--account` is a case-insensitive substring match on the key,
`bnp_<key>`, name, product or IBAN:

```bash
bnp-direct export --account "livret"
bnp-direct export --account "bnp_ABC123"
```

### Transactions (Enable Banking)

| Option | Description |
|---|---|
| `--from YYYY-MM-DD` | Start date (`date_from`). |
| `--to YYYY-MM-DD` | End date (`date_to`). |
| `--pending` | Request pending transactions only (`PDNG`). |
| `--status BOOK\|PDNG\|INFO\|OTHR` | Explicit transaction status filter. |
| `--strategy default\|longest` | Enable Banking retrieval strategy. |
| `--max-pages N` | Page limit per account (default: 50, maximum: 500). |
| `--limit N` | Keep at most N transactions per account after sorting. |
| `--raw` | Include raw Enable Banking objects (personal data). |

Transactions are fetched until Enable Banking stops returning a
`continuation_key`. A repeated key or the page limit marks the account as
`truncated: true` and adds a warning instead of looping forever.

### Export (Enable Banking)

`export` writes the full document to stdout by default. `--output PATH` writes
it atomically with mode `0600` and prints a small receipt instead.

Shell redirection does **not** apply `0600`:

```bash
# Prefer --output: the sidecar enforces 0600.
bnp-sidecar export --output "$HOME/Documents/bnp-export.json"

# If you redirect stdout yourself, protect the file explicitly.
umask 077
bnp-sidecar export > "$HOME/Documents/bnp-export.json"
```

Exports are partial by design: a per-account failure is reported in `errors[]`,
the remaining accounts are still exported, and `status` becomes `"partial"`.
Configuration, authentication and global upstream failures abort the command.

### Browser callback (Enable Banking)

With the default redirect URI (`https://localhost:8787/callback`), `auth link`
starts a local HTTPS server and opens the Enable Banking authorization URL. The
server uses a self-signed certificate generated in `cache/callback-cert.pem`
and `cache/callback-key.pem` (both `0600`). Your browser will show a
certificate warning for localhost; accepting it once is expected and only
affects the local callback.

If your Enable Banking application has an HTTP localhost redirect URI
registered, use it instead and no certificate warning is shown:

```bash
bnp-sidecar auth setup ... --redirect-uri "http://localhost:8787/callback"
```

HTTP is accepted only for loopback hosts. If the redirect URI is not local, the
sidecar cannot receive the callback itself:

```bash
# Print the URL and return immediately.
bnp-sidecar auth link --no-wait

# After the browser redirects, paste the full callback URL on stdin.
# The authorization code is then never present in argv.
bnp-sidecar auth complete --callback-url-stdin
```

The pending link expires after 15 minutes. A successful link creates a PSD2
session whose lifetime is the minimum of 180 days, the bank's maximum consent
validity, minus 60 seconds. Re-run `auth link` when it expires.

## JSON output

Every command writes one JSON object to stdout. Errors are written as one JSON
object to stderr. Dates use ISO 8601 (`YYYY-MM-DD`), timestamps use UTC ISO
8601, amounts are JSON numbers and unknown values are `null`.

| Command | Schema |
|---|---|
| `auth setup` | `bnp-sidecar/auth-setup/v1` |
| `auth link` / `auth complete` | `bnp-sidecar/auth/v1` |
| `auth status` | `bnp-sidecar/auth-status/v1` |
| `auth logout` | `bnp-sidecar/auth-logout/v1` |
| `accounts` | `bnp-sidecar/accounts/v1` |
| `transactions` | `bnp-sidecar/transactions/v1` |
| `export` | `bnp-sidecar/export/v1` |
| `export --output` | `bnp-sidecar/export-file/v1` |
| `doctor` | `bnp-sidecar/doctor/v1` |
| `bnp-direct accounts` | `bnp-sidecar/accounts/v1` (`source: "direct"`) |
| `bnp-direct export` | `bnp-sidecar/export/v1` (`source: "direct"`) |
| errors | `bnp-sidecar/error/v1` |

Example direct export (synthetic data, fields abridged):

```json
{
  "schema": "bnp-sidecar/export/v1",
  "source": "direct",
  "generatedAt": "2026-11-20T10:00:00+00:00",
  "status": "ok",
  "aspsp": "BNP Paribas",
  "country": "FR",
  "dateFrom": "2025-11-20",
  "dateTo": "2026-11-20",
  "returnedDateFrom": "2025-11-21",
  "returnedDateTo": "2026-11-19",
  "accounts": [
    {
      "uid": "ABC123",
      "externalId": "bnp_ABC123",
      "name": "Compte de chèques",
      "product": "Compte de chèques",
      "iban": null,
      "currency": "EUR",
      "type": "checking",
      "typeLabel": "Compte courant",
      "kind": "banking",
      "balance": 1234.56,
      "balanceType": "CLBD",
      "availableBalance": 1200.0,
      "availableBalanceType": "CLAV",
      "comingBalance": 0.0,
      "maskedNumber": "****1234",
      "transactions": [
        {
          "id": "OP-1",
          "dedupKey": "bnp:ABC123:OP-1",
          "bookingDate": "2026-11-18",
          "valueDate": "2026-11-18",
          "direction": "DBIT",
          "amount": -12.34,
          "currency": "EUR",
          "description": "CARREFOUR MARKET",
          "category": "Alimentation",
          "type": "card"
        }
      ],
      "transactionPages": 1,
      "transactionsTruncated": false
    }
  ],
  "totals": {
    "balances": {"EUR": 1234.56},
    "accounts": 1,
    "transactions": 1
  },
  "errors": [],
  "warnings": []
}
```

The Enable Banking export uses the same schema without `source` and adds a
`session` summary. The complete field reference is in
[docs/JSON-SCHEMAS.md](docs/JSON-SCHEMAS.md). `--raw` deliberately includes more
provider fields and must be treated as sensitive personal data.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (`doctor`: all critical checks passed). |
| `1` | Internal error, or `doctor` critical check failed. |
| `2` | Usage error. |
| `3` | Missing or invalid configuration, private key or session. |
| `4` | Authentication, consent or callback-state error. |
| `5` | Upstream or network error. |
| `7` | Account/resource not found. |

`bnp-direct` uses the same typed errors. A `probe` that loads the login page
returns `0`; a blocked or changed login page returns `UPSTREAM_ERROR` and exit
code `5`.

## Security

The full model is documented in [SECURITY.md](SECURITY.md) and
[docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md). The main guarantees are:

- **Read-only by design.** There is no payment-initiation code path, no transfer
  command, no order command and no generic HTTP passthrough. Both backends have
  explicit read-endpoint allowlists.
- **Enable Banking password boundary.** The Enable Banking backend never asks
  for, stores or transmits a BNP password. Login and SCA happen on BNP Paribas'
  pages in the browser.
- **Direct credentials are transient.** The direct backend asks for the
  customer ID and 6-digit code on the terminal for each run. The code is read
  with `getpass`, converted to keyboard positions, and discarded. It is never
  accepted in `argv`, written to a file, stored in an environment variable or
  included in JSON output.
- **No direct session persistence.** Cookies and 2FA state stay in memory for
  the duration of the process. A new login is required for each command.
- **Private files.** Sensitive files are opened with `O_NOFOLLOW`, checked as
  regular files, refused if group/other readable, capped at 64 KiB, and written
  atomically with mode `0600`. Runtime directories created by the CLI use
  `0700`.
- **Enable Banking secrets.** The RSA private key is stored separately from the
  configuration, with mode `0600`, and is never serialized into JSON. The PSD2
  session is a bearer token stored in `data/session.json` with mode `0600`.
- **OAuth callback.** The authorization `state` is 256 bits, compared in
  constant time, and expires after 15 minutes. The callback server is
  loopback-only and serves only the exact callback path.
- **Network rules.** Enable Banking mode verifies TLS, refuses HTTP redirects
  and uses a fixed API base URL. Direct mode validates every redirect against a
  BNP host allowlist before following it, and sends only read-only requests to
  allowlisted endpoints.
- **Redaction.** Logs, errors, structured details and debug tracebacks pass
  through a redaction layer. Credentials, authorization codes, JWTs, session IDs
  and private keys are never printed.

Runtime layout:

```text
~/.local/share/bnp-sidecar/
  config/config.json        0600  Enable Banking application ID, redirect URI
  config/private-key.pem    0600  Enable Banking RSA private key
  data/session.json         0600  PSD2 session (bearer token)
  data/pending-link.json    0600  OAuth state and pending authorization
  data/mfa-structure.json   0600  redacted direct-mode 2FA page structure
  cache/callback-cert.pem   0600  local self-signed TLS certificate
  cache/callback-key.pem    0600  local TLS private key
  home/                     0700  sandboxed HOME/XDG for the process
```

The direct backend does not create `config/`, `data/session.json` or
`data/pending-link.json`. It only writes `data/mfa-structure.json` when a 2FA
page is encountered.

Remove local material with:

```bash
# Revoke the remote session, then delete local session and pending link.
bnp-sidecar auth logout

# Also delete the application ID, private key and local callback certificate.
bnp-sidecar auth logout --forget

# Delete the optional direct-mode 2FA structure file.
rm -f "$HOME/.local/share/bnp-sidecar/data/mfa-structure.json"
```

`auth logout --forget` does not revoke anything at Enable Banking beyond the
session revocation attempted by the command. Delete or rotate the application
key in the Enable Banking dashboard if it may have been exposed.

Exported JSON is **not encrypted**. Store exports in a protected location,
avoid syncing them to untrusted services, and delete them when no longer
needed.

## Doctor

```bash
bnp-sidecar doctor
bnp-sidecar doctor --network
```

`doctor` checks:

- Python version;
- runtime directory permissions;
- configuration and redirect URI;
- private-key presence, format, size and public-key fingerprint;
- session presence, expiry and account count;
- pending-link state;
- with `--network`: Enable Banking reachability and BNP Paribas availability.

It reports warnings with the exact `chmod` command when a pre-existing
directory is group/other accessible. It returns exit code 1 if a critical check
fails.

`doctor` is specific to the Enable Banking backend. For direct mode, use
`bnp-direct probe` to verify that the login page is reachable and still has the
expected form.

## Development

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev,direct]"
.venv/bin/pytest
uvx ruff check bnp_sidecar tests scripts
.venv/bin/python -m compileall -q bnp_sidecar tests scripts
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
```

The automated suite never contacts Enable Banking or BNP Paribas. It uses a
local fake HTTP API, a fake direct session and synthetic accounts.

### Real-account smoke test (Enable Banking)

The manual smoke test requires an existing `auth link` session. It never asks
for a BNP password and never opens an authorization flow.

```bash
.venv/bin/python scripts/real_smoke.py
.venv/bin/python scripts/real_smoke.py --export
```

By default it prints counters, account types, dates and error codes, not
balances or IBANs. `--show-data` includes a small sample of serialized data and
is intentionally more verbose. Review the output before sharing it.

### Real-account smoke test (direct)

`bnp-direct probe`, `bnp-direct accounts` and `bnp-direct export` are the
manual checks. Use `--output` to write to a private file, then review the file
before sharing any excerpt. Never commit a real export.

## Project layout

```text
bnp_sidecar/
  cli.py             Enable Banking CLI, commands, JSON output, redaction
  client.py          read-only Enable Banking HTTP client
  config.py          configuration, redirect validation, consent cap
  jwt.py             RS256 JWT creation and key validation
  session.py         PSD2 session and pending-link persistence
  callback.py        local callback server and self-signed certificate
  serialize.py       accounts, balances and transaction JSON
  private_files.py   atomic 0600 writes and symlink-safe reads
  paths.py           runtime directories and HOME sandbox
  redact.py          secret and IBAN redaction helpers
  errors.py          typed errors and stable exit codes
  direct/
    cli.py           direct CLI, credential prompts, 2FA interaction
    client.py        direct read-only BNP web client
    login.py         login/MFA parsing and virtual-keyboard positions
scripts/real_smoke.py manual Enable Banking validation
tests/                153 unit and integration tests with fake providers
docs/                 architecture, JSON schemas and security audit
```

## Limitations

- Read-only by design; no payment, transfer or order support.
- Enable Banking mode has not been live-validated in this repository. The
  provider may expose only a subset of accounts for a given BNP profile.
- Direct mode is experimental and depends on BNP's current web pages and
  anti-bot behavior. A change on BNP's side can break login or parsing until the
  project is updated.
- Direct mode requires a new login for every command and may require manual 2FA.
  It does not persist cookies, so it cannot run unattended.
- The direct backend uses a Chrome TLS fingerprint via `curl_cffi`. This is not
  a browser and does not execute JavaScript; pages that require JavaScript
  challenges may fail.
- PSD2 consent expires; there is no background refresh daemon.
- BNP Paribas and Enable Banking can change their APIs, consent rules,
  authentication flow or anti-bot protection at any time.
- The CLI does not encrypt exports or provide certificate pinning.
- A local process running as your user can read your private files, inspect
  process memory or install a keylogger. Full-disk encryption and a dedicated
  OS account are strongly recommended.
- The default local callback uses a self-signed certificate and triggers a
  browser warning. This is expected for localhost.

## Contributing

Issues and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md)
before submitting changes. Security issues must be reported privately as
described in [SECURITY.md](SECURITY.md).

Never include real credentials, Enable Banking keys, session files, IBANs,
balances or transaction data in an issue, pull request, test fixture or commit.

## License

MIT, copyright 2026 Romain Dujardin. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).

# Architecture

```text
bnp-sidecar / bnp-cli                         bnp-direct
        |                                          |
        v                                          v
bnp_sidecar.cli                          bnp_sidecar.direct.cli
        |                                          |
        +--> config.py         EB configuration    +--> client.py   direct BNP web client
        +--> jwt.py            RS256 JWT           +--> login.py    login/2FA parsing
        +--> client.py         EB HTTP client      |
        +--> session.py        PSD2 session        +--> shared helpers:
        +--> callback.py       loopback callback       private_files.py
        +--> serialize.py      JSON shapes             paths.py
        |                                              redact.py
        v                                              errors.py
https://api.enablebanking.com                              |
        |                                                  v
        v                                      https://mabanque.bnpparibas
browser -> BNP login + SCA                              (PingFederate login + 2FA)
        |                                                  |
        v                                                  v
redirect URI -> authorization code                 read-only account endpoints
```

The project has two independent, read-only backends that share the same
private-file, path, redaction and error helpers:

- **Enable Banking**: a PSD2/AIS client. The browser performs BNP login and
  SCA; Enable Banking returns a session. The sidecar never handles a BNP
  password.
- **Direct**: a client for the BNP web application. It performs the current
  PingFederate login with a Chrome-like TLS fingerprint, handles interactive
  2FA, and calls the same read-only endpoints as the web application.

Both backends produce the same account and transaction shapes, with a
`source` field (`"direct"` for the direct backend) and backend-specific
metadata.

## Module layout

| Module | Responsibility |
|---|---|
| `bnp_sidecar/cli.py` | Enable Banking CLI, command dispatch, JSON output, redaction |
| `bnp_sidecar/client.py` | Read-only Enable Banking HTTP client |
| `bnp_sidecar/config.py` | Application ID, redirect URI, consent rules, key loading |
| `bnp_sidecar/jwt.py` | RS256 JWT creation and RSA key validation |
| `bnp_sidecar/session.py` | PSD2 session and pending OAuth link persistence |
| `bnp_sidecar/callback.py` | Loopback callback server and self-signed certificate |
| `bnp_sidecar/serialize.py` | Enable Banking account/balance/transaction JSON |
| `bnp_sidecar/direct/cli.py` | Direct CLI, credential prompts, 2FA interaction |
| `bnp_sidecar/direct/client.py` | Direct BNP web client and JSON serialization |
| `bnp_sidecar/direct/login.py` | Login page parsing, MFA parsing, keyboard positions |
| `bnp_sidecar/private_files.py` | Atomic `0600` writes and symlink-safe reads |
| `bnp_sidecar/paths.py` | Runtime directories and HOME sandbox |
| `bnp_sidecar/redact.py` | Secret and IBAN redaction helpers |
| `bnp_sidecar/errors.py` | Typed errors and stable exit codes |

## Enable Banking flow

### 1. Configuration

`bnp-sidecar auth setup`:

1. Reads the RSA private key from a `0600` file or stdin.
2. Validates the PEM, RSA type and key size (at least 2048 bits).
3. Validates the application ID, redirect URI, ASPSP name, country, PSU type
   and language.
4. Writes `config/private-key.pem` first, then `config/config.json`, both
   atomically with mode `0600`.
5. Re-reads the key to verify that the written pair is usable.

The API base URL is not user-configurable in production: it is fixed to
`https://api.enablebanking.com`. This prevents a modified configuration file
from redirecting a JWT or a PSD2 session to an arbitrary host. A loopback HTTP
base URL is accepted only by the internal test client, never by the CLI.

### 2. Authorization

`bnp-sidecar auth link`:

1. Loads the configuration and private key.
2. Refuses to replace a valid session unless `--force` is passed.
3. Calls `GET /aspsps` and locates `BNP Paribas` in the configured country.
4. Computes the consent lifetime:
   `min(180 days, bank maximum consent validity) - 60 seconds`.
5. Generates a 256-bit OAuth `state` and writes `data/pending-link.json`
   (`0600`, 15-minute expiry).
6. Calls `POST /auth` with the state, redirect URL, ASPSP, PSU type and consent
   expiry.
7. Validates that the returned authorization URL uses HTTPS.
8. If the redirect URI is loopback, starts the local callback server and opens
   the browser.
9. On callback, validates `state` in constant time, then calls
   `POST /sessions` with the authorization code.
10. Stores the session in `data/session.json` (`0600`), deletes the pending
    link and revokes the previous remote session if one existed.

If the redirect URI is not local, or `--no-wait` is used, the command prints
the authorization URL, optionally opens it, and returns without waiting. The
user then runs `auth complete --callback-url-stdin`.

### 3. Reading data

For `accounts`, `transactions` and `export`:

1. Load the configuration, private key and a non-expired session.
2. Resolve `--account` selectors against UID, IBAN, identification hash, name
   or product. An unknown or ambiguous selector is a usage error.
3. For each account, call the read-only endpoints:
   `details`, `balances`, and `transactions`.
4. Serialize the response into the versioned JSON schema.
5. On a per-account error, record it in `errors[]` and continue with the other
   accounts; set `status` to `"partial"`.

Transactions are paginated until Enable Banking stops returning
`continuation_key`. A repeated key or the configured page limit stops the loop
and marks the account as truncated.

### 4. Logout

`auth logout` attempts `DELETE /sessions/{id}` (remote revocation), then deletes
the local session and pending link. `--forget` also deletes the application
configuration, private key and local callback certificate. Remote revocation is
best-effort: a network failure is reported as a warning, not a reason to keep
local secrets.

## Direct flow

### 1. Probe

`bnp-direct probe` performs `GET https://mabanque.bnpparibas/fr/connexion` and
parses the response with `direct/login.py`. It reports:

- the final host;
- the presence of the PingFederate `#identForm` form;
- the number of keys in the virtual keyboard grid;
- the presence of the ThreatMetrix token.

It does not submit any credential. A changed page, a missing form, a missing
token or an invalid grid raises `UpstreamError` (exit code 5).

### 2. Login

`bnp-direct accounts` and `bnp-direct export`:

1. Prompt for the customer ID (7–10 digits) with `input()`.
2. Prompt for the 6-digit code with `getpass.getpass()`.
3. Register both values with the command's `Redactor`.
4. Load the login page and parse `form#identForm`, its action, the virtual
   keyboard grid (`gridPositions`) and the `pf.idTMX` token.
5. Validate that the form action host is `connexion.mabanque.bnpparibas` or
   `connexion.hellobank.fr`.
6. Convert each digit of the code to its DOM index in the grid. The bank
   expects `pf.pass.positions`, not the digits themselves.
7. Submit the form with the same browser-like headers as the login page.
8. Discard the password reference in the caller.

The form data is built with:

```text
pf.username             customer ID
pf.encryptedUsername    empty (the “remember me” box is never checked)
pf.pass.positions       six keyboard indices
pf.idTMX                page token
```

No cookie jar is created on disk. `curl_cffi.Session` keeps cookies in memory
for the process only.

### 3. MFA

After the login POST, redirects are followed with host validation. If the
resulting page is an authentication-strong page, `parse_mfa_page()` extracts:

- forms, their actions, methods, fields and buttons;
- useful links (SMS, app approval, etc.);
- candidate code fields (single field or one field per digit);
- a redacted structural description.

`is_mfa_page()` ignores authenticated pages that contain a logout link, even if
the menu mentions “Clé Digitale”. This avoids treating the dashboard as a
second-factor page.

The CLI then chooses an interaction:

- `sms`: read a numeric code with `getpass`;
- `approval`: ask the user to approve in the BNP application and press Enter;
- `form` / `link`: print numbered actions and let the user choose one;
- `unknown`: print the available actions, or fail if none are recognized.

The structural description is written to `data/mfa-structure.json` (`0600`) to
help diagnose page changes. It contains no field value, code, cookie or
authorization header. The body excerpt has digit runs replaced with `<N>`.

### 4. Reading data

After login, the client verifies the session with
`GET /serviceinfosclient-wspl/rpc/InfosClient?modeAppel=0`, then:

| Step | Request | Purpose |
|---|---|---|
| Accounts | `GET /udc-wspl/rest/getlstcpt` | Account families, balances, masked numbers |
| RIBs | `GET /rib-wspl/rpc/comptes` | Encrypted account keys and IBAN/RIB values |
| Recent history | `POST /rop2-wspl/rest/releveOp` | Roughly the last year |
| Legacy history | `POST /rop-wspl/rest/releveOp` | Older history, clamped to three years |

The transaction body is:

```json
{
  "ibanCrypte": "<account key>",
  "pastOrPending": 1,
  "triAV": 0,
  "startDate": "DDMMYYYY",
  "endDate": "DDMMYYYY"
}
```

`ibanCrypte` is the opaque BNP account key, not a plain IBAN. The key is also
used as the account `uid` and in `dedupKey`.

### 5. Export

`export`:

1. Parses `--until` (default today) and `--since` (default one year before
   `--until`; a 29 February start is clamped to 28 February in the previous
   year).
2. Reads all accounts and applies `--account` selectors.
3. For each selected account, reads transactions and sorts them newest first.
4. Records per-account failures in `errors[]` and marks the account
   `transactionsTruncated: true`.
5. Computes `returnedDateFrom` / `returnedDateTo` from the actual transaction
   booking dates.
6. Writes the document to stdout or to a private `0600` file with `--output`.

## Login and MFA parsing

`direct/login.py` contains two HTML parsers:

- `_LoginPageParser` extracts the form action, inputs, element IDs and scripts
  from the PingFederate page.
- `_MfaPageParser` extracts forms, fields, buttons, links, scripts and iframes
  from a 2FA page, while keeping field values out of the public structure.

The MFA structure is deliberately descriptive rather than raw HTML:

```json
{
  "kind": "sms",
  "page": {"host": "mabanque.bnpparibas", "path": "/fr/secure/...", "queryKeys": []},
  "forms": [
    {
      "id": null,
      "actionHost": "mabanque.bnpparibas",
      "actionPath": "/fr/secure/valider",
      "actionQueryKeys": [],
      "method": "post",
      "fields": [{"name": "code", "type": "text", "inputmode": "numeric"}],
      "buttons": [{"label": "Valider", "type": "submit", "name": null}]
    }
  ],
  "links": [],
  "scripts": [],
  "iframes": [],
  "bodyExcerpt": "Un code a été envoyé à votre téléphone."
}
```

Numeric runs in labels and body text are replaced with `<N>`. Values such as
`csrf` tokens, cookies and the submitted code are never included.

## HTTP rules

### Enable Banking

`EnableBankingClient` exposes only account-information operations:

| Method | Endpoint |
|---|---|
| `get_application` | `GET /application` |
| `list_aspsps` / `find_aspsp` | `GET /aspsps` |
| `start_authorization` | `POST /auth` |
| `create_session` | `POST /sessions` |
| `get_session` | `GET /sessions/{id}` |
| `delete_session` | `DELETE /sessions/{id}` |
| `get_account_details` | `GET /accounts/{uid}/details` |
| `get_account_balances` | `GET /accounts/{uid}/balances` |
| `get_transactions_page` | `GET /accounts/{uid}/transactions` |
| `get_all_transactions` | paginated wrapper |

There is no generic request method exposed to the CLI and no payment-related
code path.

Transport rules:

- TLS verification is the Python default and is never disabled;
- HTTP redirects are refused, not followed;
- the response body is capped at 16 MiB;
- `Accept-Encoding: identity` avoids compression handling;
- the timeout defaults to 30 seconds and is bounded to 1–120 seconds;
- a non-JSON body is an upstream error;
- HTTP 401/403, 404, 429 and 5xx responses map to typed errors.

### Direct

`BnpDirectClient` exposes:

- `probe_login_page()`;
- `login(customer_id, password)`;
- `accounts()`;
- `transactions(account, since, until)`;
- `accounts_payload()`;
- `export(...)`.

Data requests go through `_get_json()` and `_post_json()`, which call
`_endpoint_allowed()` before sending anything. The allowlist is:

```text
GET  /serviceinfosclient-wspl/rpc/InfosClient
GET  /udc-wspl/rest/getlstcpt
GET  /rib-wspl/rpc/comptes
POST /rop2-wspl/rest/releveOp
POST /rop-wspl/rest/releveOp
```

`_read_request()` disables automatic redirects, checks the next URL against the
BNP host allowlist, converts a `301/302/303` to a `GET` without body, preserves
`307/308` method and body, and caps the chain at 10 hops. The final response
URL is checked again. This prevents `curl_cffi` from silently following a
redirect to an arbitrary domain with the BNP session cookie.

The login `POST` and 2FA requests are also sent with `allow_redirects=False` and
followed with the same host validation. The login form action and every MFA
form/link host are validated before use.

## Balances

### Enable Banking

Enable Banking returns a list of balance objects. The sidecar normalizes each
one and selects:

- **booked balance**: `CLBD`, then `ITBD`, `PRCD`, `XPCD`, `FWAV`,
  `expected`, `closingBooked`;
- **available balance**: `CLAV`, then `ITAV`, `OPAV`, `XPCD`, `FWAV`,
  `expected`.

If no preferred type exists, the first normalized balance is used as the
booked balance, and the available balance falls back to the booked one. The
complete normalized list remains in `balances[]`.

### Direct

`getlstcpt` returns account families and account objects. The sidecar maps:

- `soldeComptable` → `balance` (`CLBD`, booked);
- `soldeDispo` → `availableBalance` (`CLAV`);
- `soldeAVenir` → `comingBalance`;
- `solde` and `soldeDispo` are fallbacks when `soldeComptable` is absent;
- `value` → `maskedNumber` (for example `****1234`);
- `devise` → `currency` (default `EUR`);
- `key` or `ibanCrypte` → `uid`.

A `CLAV` balance object is added only when the available balance differs from
the booked balance. This keeps the common case compact.

## Transactions

### Enable Banking

Transactions are normalized as follows:

- `transaction_amount` is parsed with `Decimal` to avoid binary floating-point
  rounding;
- `DBIT` becomes negative, `CRDT` becomes positive;
- the description comes from `remittance_information`, then the bank
  transaction code, note or counterparty name;
- a stable `id` uses `entry_reference`, `transaction_id` or
  `reference_number`; otherwise it is a SHA-256 hash of account, dates, amount,
  direction, description and page index;
- `dedupKey` is `bnp:<accountUid>:<id>`;
- results are sorted by booking date, then value date, then transaction date,
  newest first, preserving the original order for identical dates.

`--limit` is applied after sorting. `pages`, `truncated` and `limited` describe
what happened during retrieval.

### Direct

Each `operationPassee` item becomes a transaction:

- `idOperation` is the `id`; if absent, a SHA-256 hash of account, date, amount,
  label and index is used;
- `dedupKey` is `bnp:<accountKey>:<id>`;
- `dateOperation` and `montant.valueDate` are normalized to `YYYY-MM-DD`;
- `montant.montant` is parsed with `Decimal`;
- `libelleOperation` becomes `description` and `descriptionLines`;
- `operationType.codeFamille` maps to a normalized `type` (`card`, `transfer`,
  `check`, `cash_deposit`, `loan_payment`, `securities`, `withdrawal`,
  `international`, `bank_fee`, `other`);
- `categorie` is passed through as `category`;
- `direction` is `DBIT` for a negative amount and `CRDT` otherwise;
- `status` is `BOOK` (the endpoint returns past operations).

The current endpoint and the legacy endpoint are merged by `idOperation`.
Identical IDs are deduplicated; distinct operations with the same label and
amount are kept. The legacy query is clamped to three years.

## Account types

Both backends emit lowercase normalized types:

| `type` | `typeLabel` | `kind` |
|---|---|---|
| `checking` | Compte courant | `banking` |
| `savings` | Épargne | `savings` |
| `pea` | PEA | `trading` |
| `securities` | Compte-titres | `trading` |
| `employee_savings` | Épargne salariale | `trading` |
| `life_insurance` | Assurance-vie | `insurance` |
| `loan` | Crédit | `loan` |
| `card` | Carte | `banking` |
| `deposit` | Dépôt | `deposit` |
| `unknown` | Compte | `unknown` |

Enable Banking type detection uses the account name, product and cash-account
type. Direct type detection first inspects the product label (PEA, livret,
assurance-vie, crédit), then falls back to the BNP account family:

| BNP family | Type |
|---:|---|
| 1 | `checking` |
| 2 | `savings` |
| 3 | `deposit` |
| 4 | `securities` (or `pea` when the label says PEA) |
| 5, 6 | `life_insurance` |
| 8, 9 | `loan` |

These are presentation heuristics, not an authoritative bank classification.

## IBAN and RIB handling

Direct accounts may expose:

- an encrypted account key (`key` / `ibanCrypte`), always used as the account
  identifier;
- an IBAN in `getlstcpt`;
- an IBAN in `rib-wspl/rpc/comptes`;
- a 21- or 23-digit French RIB instead of an IBAN.

`normalize_iban()` validates the MOD-97 checksum and only accepts a
well-formed IBAN. `rib_to_iban()` recomputes the RIB key, builds the French
IBAN, validates it with the same MOD-97 check, and returns `None` if any step
fails. When no valid IBAN exists, `iban` is `null`; the account key remains
stable across runs.

## Storage layout

```text
~/.local/share/bnp-sidecar/
  config/config.json        0600  Enable Banking application ID, redirect URI
  config/private-key.pem    0600  Enable Banking RSA private key
  data/session.json         0600  PSD2 session (bearer token)
  data/pending-link.json    0600  OAuth state and pending authorization
  data/mfa-structure.json   0600  redacted direct-mode 2FA page structure
  cache/callback-cert.pem   0600  local self-signed TLS certificate
  cache/callback-key.pem    0600  local TLS private key
  home/                     0700  sandboxed HOME/XDG
```

`paths.apply_sandbox_env()` redirects `HOME`, `XDG_CONFIG_HOME`,
`XDG_DATA_HOME` and `XDG_CACHE_HOME` into `home/`, `config/`, `data/` and
`cache/` for the duration of an Enable Banking command. `cryptography` does not
need these directories, so this is defense in depth rather than a functional
requirement. The direct command does not create or use the sandbox.

Directories created by the CLI use `0700`. Pre-existing directories are not
chmodded; `doctor` reports insecure modes.

## Error model

`errors.py` defines typed exceptions with stable codes and exit codes:

| Exception | Code | Exit |
|---|---|---|
| `UsageError` | `USAGE_ERROR` | 2 |
| `ConfigError` / `SecretFileError` | `CONFIG_ERROR` / `SECRET_FILE_ERROR` | 3 |
| `SessionError` / `SessionExpired` | `SESSION_ERROR` / `SESSION_EXPIRED` | 3 |
| `AuthenticationError` | `AUTH_FAILED` | 4 |
| `ConsentDenied` | `CONSENT_DENIED` | 4 |
| `LinkStateError` | `LINK_STATE_INVALID` | 4 |
| `UpstreamError` | `UPSTREAM_ERROR` | 5 |
| `NotFoundError` | `NOT_FOUND` | 7 |
| `AmbiguousAccount` | `AMBIGUOUS_ACCOUNT` | 7 |
| `DirectMFARequired` | `MFA_REQUIRED` | 4 |
| any other exception | `INTERNAL_ERROR` | 1 |

Expected errors become `bnp-sidecar/error/v1` JSON on stderr. Authentication,
configuration and global upstream failures abort a command. Per-account
failures are collected in `errors[]` and produce `status: "partial"`.

The direct CLI catches any unexpected exception at the top level, redacts it and
returns `INTERNAL_ERROR` JSON instead of a traceback. Argparse errors are also
converted to `USAGE_ERROR`.

## Testing strategy

- `tests/conftest.py` provides a generated RSA key and a deterministic fake
  Enable Banking client.
- `tests/test_client.py` starts a local HTTP server on `127.0.0.1` and exercises
  JWT headers, authorization payloads, pagination, redirects, timeouts, error
  mapping and response limits.
- `tests/test_callback.py` starts real loopback servers over HTTP and checks
  state validation, denial, timeout and the HTTPS certificate.
- `tests/test_cli.py` drives the Enable Banking CLI through `main()` with
  injected clients and a fake browser opener. It covers setup, link, complete,
  status, logout, accounts, transactions, export, doctor and error redaction.
- `tests/test_direct_login.py` covers login-page parsing, keyboard positions,
  MFA detection and redacted structures.
- `tests/test_direct_client.py` covers the direct account/transaction parsers,
  balance selection, history merging, redirect validation, read-endpoint
  allowlist, account selection and export edge cases.
- `tests/test_direct_cli.py` covers `probe`, 2FA prompting, action filtering and
  error redaction.

No test contacts Enable Banking or BNP Paribas. The `real` and `network`
markers are reserved for manual smoke tests.

`scripts/real_smoke.py` is the manual Enable Banking end-to-end check. It uses
an existing session, reports counters and error codes, and never prompts for a
BNP password. Direct mode is checked manually with `bnp-direct probe`,
`bnp-direct accounts` and `bnp-direct export`.

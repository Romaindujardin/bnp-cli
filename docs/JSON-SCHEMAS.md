# JSON schemas

Every command writes exactly one JSON object to stdout on success. Errors are
written as one JSON object to stderr. The schemas are versioned in the
`schema` field; new fields are additive and existing field names are kept
stable within a major schema version.

The project has two backends:

- **Enable Banking** (`bnp-sidecar` / `bnp-cli`) produces the auth, accounts,
  transactions, export and doctor schemas below.
- **Direct** (`bnp-direct`) reuses `bnp-sidecar/accounts/v1` and
  `bnp-sidecar/export/v1` with `source: "direct"`, and has no auth, session or
  doctor document. Direct payloads omit the `session` object and add
  direct-mode fields such as `maskedNumber`, `comingBalance`, `category` and
  `type`.

Conventions:

- timestamps are UTC ISO 8601 with an explicit offset;
- dates are `YYYY-MM-DD`;
- amounts are JSON numbers, not strings;
- unknown or unavailable values are `null`;
- arrays are `[]`, never `null` unless stated otherwise;
- identifiers, IBANs, names and transaction labels are personal data.

No schema contains a BNP Paribas password, a 6-digit code, a 2FA code,
session cookies, an Enable Banking private key, a JWT or an authorization code.
`--raw` is the explicit exception for raw provider payloads.

## `bnp-sidecar/error/v1`

Written to stderr for every expected failure, by both backends.

| Field | Type | Description |
|---|---|---|
| `schema` | string | `bnp-sidecar/error/v1`. |
| `ok` | boolean | Always `false`. |
| `error.code` | string | Stable error code. |
| `error.message` | string | Redacted human-readable message. |
| `error.details` | object | Redacted structured details; may be empty. |
| `error.traceback` | string | Present only with `--debug` on the Enable Banking CLI; redacted. |

Common codes: `USAGE_ERROR`, `CONFIG_ERROR`, `SECRET_FILE_ERROR`,
`SESSION_ERROR`, `SESSION_EXPIRED`, `AUTH_FAILED`, `CONSENT_DENIED`,
`LINK_STATE_INVALID`, `MFA_REQUIRED`, `UPSTREAM_ERROR`, `NOT_FOUND`,
`AMBIGUOUS_ACCOUNT`, `INTERNAL_ERROR`.

## `bnp-sidecar/auth-setup/v1`

Output of `auth setup`.

| Field | Type | Description |
|---|---|---|
| `schema` | string | `bnp-sidecar/auth-setup/v1`. |
| `generatedAt` | string | Generation timestamp. |
| `ok` | boolean | `true`. |
| `result` | string | `configured`. |
| `applicationIdMasked` | string | First eight characters of the application ID, then `…`. |
| `keyFingerprint` | string | First 16 hex characters of the SHA-256 of the public key DER. |
| `redirectUri` | string | Registered redirect URI. |
| `aspsp` | string | ASPSP name, default `BNP Paribas`. |
| `country` | string | ISO 3166-1 alpha-2 country, default `FR`. |
| `psuType` | string | `personal` or `business`. |
| `storage.configFile` | object | Private file metadata (`path`, `exists`, `symlink`, `mode`, `size`, `regular`). |
| `storage.privateKeyFile` | object | Private file metadata. |
| `next` | string | Suggested next command. |

The private key content and the full application ID are never included.

## `bnp-sidecar/auth/v1`

Output of `auth link` and `auth complete`. Two variants share the schema name.

### Pending variant

| Field | Type | Description |
|---|---|---|
| `schema` | string | `bnp-sidecar/auth/v1`. |
| `generatedAt` | string | Generation timestamp. |
| `ok` | boolean | `true`. |
| `status` | string | `pending`. |
| `result` | string | `pending`. |
| `authUrl` | string | Enable Banking authorization URL. Treat it as sensitive: it starts a consent flow. |
| `aspsp` | string | ASPSP name. |
| `redirectUri` | string | Redirect URI used for this link. |
| `expiresAt` | string | Pending-link expiry (15 minutes). |
| `consentValidUntil` | string | Requested PSD2 consent expiry. |
| `waiting` | boolean | `false` in the current pending output. |
| `instructions` | string | Human instructions for manual completion. |

The OAuth `state` is never included.

### Linked variant

| Field | Type | Description |
|---|---|---|
| `schema` | string | `bnp-sidecar/auth/v1`. |
| `generatedAt` | string | Generation timestamp. |
| `ok` | boolean | `true`. |
| `status` | string | `linked`. |
| `result` | string | `linked`. |
| `aspsp` | string | ASPSP name. |
| `session` | object | Session summary, see below. |
| `accounts` | array | Account summaries: `name`, `product`, `currency`, `ibanMasked`. |
| `storage.sessionFile` | string | Absolute path of the session file. |
| `storage.mode` | string | `600`. |
| `warnings` | array of strings | Non-fatal warnings, for example a failed revocation of the previous session. |

The full session identifier and full IBAN are never included.

## Session summary

Used in `auth`, `accounts`, `transactions`, `export` and `doctor`.

| Field | Type | Description |
|---|---|---|
| `idMasked` | string | First four and last four characters of the session ID, separated by `…`. |
| `status` | string | Provider status (`AUTHORIZED`, …) or `EXPIRED`. |
| `createdAt` | string | Local link creation timestamp. |
| `authorizedAt` | string | Authorization timestamp. |
| `validUntil` | string | Consent expiry. |
| `expiresAt` | string | Alias of `validUntil`. |
| `expired` | boolean | Whether the session is expired at generation time. |
| `daysRemaining` | integer or null | Whole days remaining, floor, minimum 0. |
| `aspsp` | string | ASPSP name. |
| `country` | string | ASPSP country. |
| `psuType` | string | `personal` or `business`. |
| `accounts` | integer | Number of accounts in the session. |

## `bnp-sidecar/auth-status/v1`

Output of `auth status`.

| Field | Type | Description |
|---|---|---|
| `schema` | string | `bnp-sidecar/auth-status/v1`. |
| `generatedAt` | string | Generation timestamp. |
| `ok` | boolean | `true` when both configuration and private key are usable. |
| `configured` | boolean | Configuration and private key are present and valid. |
| `ready` | boolean | Configured and a non-expired session exists. |
| `config` | object or null | `applicationIdMasked`, `redirectUri`, `aspsp`, `country`, `psuType`, `language`, `baseUrl`, `keyFingerprint`, `privateKey` metadata. |
| `session` | object or null | Session summary. |
| `pendingLink` | object | `{"present": false}` or `present`, `expiresAt`, `expired`, `aspsp`. |
| `storage` | object | `root`, `configFile`, `privateKeyFile`, `sessionFile`, `pendingLinkFile` metadata. |
| `warnings` | array of strings | Configuration, key or session problems. |

Private file metadata fields are `path`, `exists`, `symlink`, `mode` (octal
string), `size` (bytes) and `regular`.

## `bnp-sidecar/auth-logout/v1`

| Field | Type | Description |
|---|---|---|
| `schema` | string | `bnp-sidecar/auth-logout/v1`. |
| `generatedAt` | string | Generation timestamp. |
| `ok` | boolean | `true`. |
| `result` | string | `logged_out`. |
| `sessionDeleted` | boolean | Local session file was deleted. |
| `remoteSessionRevoked` | boolean | `DELETE /sessions/{id}` succeeded. |
| `pendingLinkDeleted` | boolean | Pending link file was deleted. |
| `configDeleted` | array of strings | Files deleted by `--forget`. |
| `forgot` | boolean | `--forget` was passed. |
| `warnings` | array of strings | Remote revocation or file deletion problems. |

## `bnp-sidecar/accounts/v1`

Output of `accounts` (Enable Banking) and `bnp-direct accounts`.

| Field | Type | Description |
|---|---|---|
| `schema` | string | `bnp-sidecar/accounts/v1`. |
| `source` | string | Present for direct mode: `direct`. |
| `generatedAt` | string | Generation timestamp. |
| `aspsp` | string | ASPSP name. |
| `country` | string | ASPSP country. |
| `session` | object | Enable Banking session summary; absent in direct mode. |
| `accounts` | array | Serialized accounts, see below. |
| `totals.balances` | object | Sum of `balance` by currency: `{"EUR": 1234.5}`. |
| `status` | string | `ok` or `partial`. Direct accounts are `ok`. |
| `errors` | array | Per-account errors: `account`, `step`, `code`, `message`. |
| `warnings` | array of strings | Command warnings. |

The direct variant has `source: "direct"`, no `session` field, and
`status: "ok"` / `errors: []` because account-list failures abort the command
before a document is produced.

## Account object

| Field | Type | Description |
|---|---|---|
| `uid` | string | Enable Banking account UID (EB) or BNP account key (direct). Stable for the session/account. |
| `externalId` | string | `identification_hash`, a SHA-256-derived IBAN identifier, `uid:<uid>` (EB), or `bnp_<key>` (direct). |
| `identificationHash` | string or null | Enable Banking identification hash. Always `null` in direct mode. |
| `name` | string | Account name, product or `Compte bancaire`. |
| `product` | string or null | Product label. |
| `iban` | string or null | Full IBAN. Personal data. Direct mode may return `null` when only a RIB or an encrypted key is available. |
| `currency` | string | ISO 4217 code, default `EUR`. |
| `type` | string | Normalized lowercase account type, see below. |
| `typeLabel` | string | French human label. |
| `kind` | string | `banking`, `savings`, `trading`, `insurance`, `loan`, `deposit` or `unknown`. |
| `cashAccountType` | string or null | Enable Banking `cash_account_type`. Always `null` in direct mode. |
| `usage` | string or null | Enable Banking usage. Always `null` in direct mode. |
| `balance` | number or null | Booked balance (`CLBD`). Direct mode uses `soldeComptable`. |
| `balanceType` | string or null | Selected balance type, usually `CLBD`. |
| `balanceDate` | string or null | Reference date of the booked balance. |
| `availableBalance` | number or null | Available balance (`CLAV`). Direct mode uses `soldeDispo`. |
| `availableBalanceType` | string or null | Selected available balance type, usually `CLAV`. |
| `creditLimit` | number or null | Credit limit when provided. Always `null` in direct mode. |
| `balances` | array | All normalized balances, see below. |
| `comingBalance` | number or null | Direct only: `soldeAVenir`. |
| `maskedNumber` | string or null | Direct only: masked account number, for example `****1234`. |
| `raw` | object | Present only with `--raw`: Enable Banking `details`/`balances`, or the raw BNP account object in direct mode. |

Account type values:

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

Type detection uses the account name, product and cash-account type for Enable
Banking, and the BNP product label plus account family for direct mode. It is a
presentation heuristic, not an authoritative bank classification.

## Balance object

| Field | Type | Description |
|---|---|---|
| `type` | string or null | Enable Banking `balance_type`, for example `CLBD`, `CLAV`, `ITAV`, `OPAV`. Direct mode uses `CLBD` for the booked balance and `CLAV` for a distinct available balance. |
| `name` | string or null | Provider label. Direct mode uses `Solde` / `Solde disponible`. |
| `amount` | number | Balance amount. |
| `currency` | string | ISO 4217 code, default `EUR`. |
| `referenceDate` | string or null | `YYYY-MM-DD`. |
| `lastChangeDateTime` | string or null | Provider timestamp, passed through as text. Always `null` in direct mode. |

## `bnp-sidecar/transactions/v1`

Output of `transactions`.

| Field | Type | Description |
|---|---|---|
| `schema` | string | `bnp-sidecar/transactions/v1`. |
| `generatedAt` | string | Generation timestamp. |
| `aspsp` | string | ASPSP name. |
| `session` | object | Session summary. |
| `dateFrom` | string or null | Effective `--from`. |
| `dateTo` | string or null | Effective `--to`. |
| `transactionStatus` | string or null | `BOOK`, `PDNG`, `INFO`, `OTHR`, or null. |
| `strategy` | string | `default` or `longest`. |
| `status` | string | `ok` or `partial`. |
| `accounts` | array | Per-account transaction payloads. |
| `summary.accounts` | integer | Number of accounts with a successful response. |
| `summary.transactions` | integer | Total transactions returned. |
| `errors` | array | Per-account errors: `account`, `step`, `code`, `message`. |
| `warnings` | array of strings | Pagination, limit or per-account warnings. |

Per-account transaction payload:

| Field | Type | Description |
|---|---|---|
| `uid` | string | Account UID. |
| `name` | string or null | Account name. |
| `product` | string or null | Product. |
| `iban` | string or null | Full IBAN. Personal data. |
| `currency` | string or null | Account currency. |
| `transactions` | array | Transaction objects, see below. |
| `pages` | integer | Number of fetched pages. |
| `truncated` | boolean | Pagination stopped on a repeated key or page limit. |
| `limited` | boolean | `--limit` removed transactions. |
| `warnings` | array of strings | Account-level warnings. |

## Transaction object

| Field | Type | Description |
|---|---|---|
| `id` | string | `entry_reference`, `transaction_id`, `reference_number`, or a stable SHA-256-derived identifier. |
| `dedupKey` | string | `bnp:<accountUid>:<id>`. |
| `entryReference` | string or null | Provider entry reference. |
| `transactionId` | string or null | Provider transaction ID. |
| `bookingDate` | string or null | `YYYY-MM-DD`. |
| `valueDate` | string or null | `YYYY-MM-DD`. |
| `transactionDate` | string or null | `YYYY-MM-DD`. |
| `status` | string or null | `BOOK`, `PDNG`, `INFO`, `OTHR`, or provider value. |
| `direction` | string or null | `DBIT` or `CRDT`. |
| `amount` | number | Signed amount: negative for `DBIT`, positive otherwise. |
| `currency` | string | ISO 4217 code, default `EUR`. |
| `description` | string | Joined description lines or a fallback label. |
| `descriptionLines` | array of strings | Individual description lines. |
| `counterparty` | object or null | `name` and `iban` of the relevant counterparty. |
| `merchantCategoryCode` | string or null | MCC when provided. |
| `referenceNumber` | string or null | Provider reference. |
| `bankTransactionCode` | string or null | Bank transaction code. |
| `bankTransactionLabel` | string or null | Bank transaction code description. |
| `balanceAfter` | number or null | Balance after the transaction when provided. Always `null` in direct mode. |
| `note` | string or null | Provider note. Always `null` in direct mode. |
| `category` | string or null | Direct only: BNP category label when provided. |
| `type` | string or null | Direct only: normalized transaction type (`card`, `transfer`, `check`, `cash_deposit`, `loan_payment`, `securities`, `withdrawal`, `international`, `bank_fee`, `other`). |
| `raw` | object | Present only with `--raw`: the raw Enable Banking transaction or raw BNP operation. |

For `DBIT`, the counterparty is the creditor; for `CRDT`, the debtor. The
serializer falls back to the other side when only one side is populated.

In direct mode, `entryReference` and `transactionId` both contain the BNP
`idOperation` (or the generated fallback hash), `status` is `"BOOK"`,
`transactionDate` equals `bookingDate`, and `counterparty`, `merchantCategoryCode`,
`referenceNumber`, `bankTransactionCode`, `bankTransactionLabel`,
`balanceAfter` and `note` are `null`.

## `bnp-sidecar/export/v1`

Output of `export` (Enable Banking) and `bnp-direct export` without `--output`.

| Field | Type | Description |
|---|---|---|
| `schema` | string | `bnp-sidecar/export/v1`. |
| `source` | string | Present for direct mode: `direct`. |
| `generatedAt` | string | Generation timestamp. |
| `status` | string | `ok` or `partial`. |
| `aspsp` | string | ASPSP name. |
| `country` | string | ASPSP country. |
| `session` | object | Enable Banking session summary; absent in direct mode. |
| `dateFrom` | string or null | Effective `--from` / `--since`. |
| `dateTo` | string or null | Effective `--to` / `--until`. |
| `returnedDateFrom` | string or null | Direct only: earliest `bookingDate` actually returned. |
| `returnedDateTo` | string or null | Direct only: latest `bookingDate` actually returned. |
| `transactionStatus` | string or null | Effective status filter (Enable Banking only). |
| `strategy` | string | `default` or `longest` (Enable Banking only). |
| `accounts` | array | Serialized accounts with embedded transactions. |
| `totals.balances` | object | Sum of account balances by currency. |
| `totals.accounts` | integer | Number of exported accounts. |
| `totals.transactions` | integer | Number of embedded transactions. |
| `errors` | array | Per-account or per-step errors. |
| `warnings` | array of strings | Command warnings. |

Each export account is the account object above plus:

| Field | Type | Description |
|---|---|---|
| `transactions` | array | Transaction objects. Empty if the transaction step failed or `--no-transactions` was used. |
| `transactionPages` | integer | Fetched pages. Direct mode always reports `1`. |
| `transactionsTruncated` | boolean | Pagination was truncated, or the transaction step failed. |
| `transactionsLimited` | boolean | Present when the transaction step succeeded; `--limit` removed transactions (Enable Banking only). |

If an Enable Banking account details or balance step fails, a placeholder
account is included with empty transactions, `transactionPages: 0`,
`transactionsTruncated: true` and no `transactionsLimited` field.

In direct mode, a per-account transaction failure keeps the account and its
balances, sets `transactionsTruncated: true`, and records an entry in `errors[]`
with `account`, `step`, `code` and `message`. The command then returns
`status: "partial"`.

## `bnp-sidecar/export-file/v1`

Output of `export --output PATH` (the export document is written to the file).

| Field | Type | Description |
|---|---|---|
| `schema` | string | `bnp-sidecar/export-file/v1`. |
| `generatedAt` | string | Same timestamp as the export document. |
| `ok` | boolean | `true`. |
| `status` | string | `ok` or `partial`. |
| `path` | string | Absolute path of the written file. |
| `mode` | string | `600`. |
| `accounts` | integer | Number of accounts. |
| `transactions` | integer | Number of transactions. |
| `warnings` | array of strings | Command warnings. |

The target file is written atomically and forced to `0600`. A symlink target is
refused.

## `bnp-sidecar/doctor/v1`

| Field | Type | Description |
|---|---|---|
| `schema` | string | `bnp-sidecar/doctor/v1`. |
| `generatedAt` | string | Generation timestamp. |
| `ok` | boolean | All critical checks passed. |
| `configured` | boolean | Configuration and private key are usable. |
| `ready` | boolean | Configured and a non-expired session exists. |
| `checks` | array | Check objects. |
| `warnings` | array of strings | Human-readable warnings. |
| `session` | object or null | Session summary. |

Each check:

| Field | Type | Description |
|---|---|---|
| `name` | string | `python`, `storage`, `config`, `private-key`, `session`, `pending-link`, `network` or `aspsp`. |
| `ok` | boolean | Check result. |
| `critical` | boolean | Whether failure makes the command exit 1. |
| `detail` | string | Redacted detail. |

The command exits 1 when any critical check fails, otherwise 0.

## `bnp-sidecar/mfa-structure/v1` (internal)

Written by `bnp-direct` to `data/mfa-structure.json` when a 2FA page is
encountered. It is a diagnostic file, not a command output. It has no version
field, but its shape is stable within 0.x.

| Field | Type | Description |
|---|---|---|
| `kind` | string | `sms`, `approval` or `unknown`. |
| `page.host` | string | Page host. |
| `page.path` | string | Page path with numeric segments and long IDs masked. |
| `page.queryKeys` | array of strings | Query parameter names only; values are omitted. |
| `titleLength` | integer | Length of the page title. |
| `forms` | array | Forms with `id`, `actionHost`, `actionPath`, `actionQueryKeys`, `method`, `fields` and `buttons`. |
| `forms[].fields` | array | Field `name`, `type`, `id`, `inputmode`, `autocomplete` and `maxlength`. Values are omitted. |
| `forms[].buttons` | array | Button `label` (digits masked), `type` and `name`. |
| `links` | array | Link `label` (digits masked), `host`, `path` and `queryKeys`. |
| `scripts` | array | Script/iframe hosts and paths when present. |
| `iframes` | array | Iframe hosts and paths when present. |
| `bodyExcerpt` | string | First 600 characters of visible text, with digit runs replaced by `<N>`. |

No field value, code, cookie, authorization header or submitted password is
included. The file can still contain page text, so treat it as sensitive and
delete it when it is no longer needed.

## Privacy notes

- `accounts[].iban`, `accounts[].maskedNumber`, `transactions[].iban`, `name`,
  `description`, `counterparty`, merchant data, `category` and raw payloads are
  personal data.
- `authUrl` starts an authorization flow and should not be shared.
- `--raw` includes provider payloads that may contain more personal data than
  the normalized schema.
- `mfa-structure.json` can contain page text. It contains no credentials but
  should still be handled as private data.
- Exports are not encrypted by the sidecar.
- Error messages and details are redacted, but you should still review
  diagnostics before sharing them.

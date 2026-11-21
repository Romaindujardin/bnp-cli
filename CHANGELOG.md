# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-21

Adds an experimental direct BNP Paribas web backend alongside the Enable
Banking PSD2 backend. The project remains read-only.

### Added

- `bnp-direct` command with `probe`, `accounts` and `export` subcommands.
- Chrome-like TLS fingerprint through the optional `curl_cffi` dependency
  (`pip install "bnp-sidecar[direct]"`).
- Current PingFederate login support: `#identForm`, virtual keyboard
  `gridPositions`, `pf.idTMX`, and keyboard-position encoding for the 6-digit
  code.
- Interactive 2FA support for SMS codes, app approval, forms and validation
  links, with a redacted structural description written to
  `data/mfa-structure.json` (`0600`).
- Read-only direct endpoint allowlist: account list, RIBs, recent operations and
  legacy history fallback. Redirects are validated hop by hop against a BNP host
  allowlist.
- Transaction history merge between `/rop2-wspl/rest/releveOp` and the legacy
  `/rop-wspl/rest/releveOp`, deduplicated by `idOperation`, with a three-year
  clamp.
- French RIB (21/23 digits) to IBAN conversion with checksum validation.
- Direct account payloads with `source: "direct"`, `maskedNumber`,
  `comingBalance`, booked balance from `soldeComptable`, available balance from
  `soldeDispo`, and lowercase normalized account types.
- `returnedDateFrom` / `returnedDateTo` in direct exports.
- Direct error payloads use `bnp-sidecar/error/v1` with redacted messages and
  details; unexpected exceptions become `INTERNAL_ERROR` instead of a
  traceback.
- Documentation for both backends in `README.md`, `SECURITY.md`,
  `docs/ARCHITECTURE.md`, `docs/JSON-SCHEMAS.md` and
  `docs/SECURITY-AUDIT.md`.

### Changed

- Version bumped to `0.2.0`.
- Description and keywords updated to mention the direct backend.
- Account types are lowercase in direct output, matching the Enable Banking
  schema (`checking`, `savings`, `loan`, …).
- The direct one-year default export range handles a 29 February end date.

### Security

- The direct 6-digit code is read with `getpass`, converted to keyboard
  positions, and never written to disk, `argv`, an environment variable or a
  log. It is not reused between runs.
- Direct session cookies and 2FA state stay in memory only.
- Direct customer ID and code are registered with the redaction layer.
- Direct data requests disable automatic redirects and validate every hop and
  the final host against the BNP allowlist.
- The optional 2FA structure file contains no field values, codes, cookies or
  authorization headers, is written atomically with mode `0600`, and its runtime
  root is created with mode `0700`.
- The Enable Banking security model is unchanged: no BNP password, separate
  `0600` RSA key, `0600` PSD2 session, validated callback and redacted errors.
- Read-only endpoint allowlists are enforced for both backends.

### Validation

- Automated suite: **153 tests**, no network access, using fake providers and
  synthetic accounts.
- `ruff check bnp_sidecar tests scripts`: clean.
- `python -m compileall -q bnp_sidecar tests scripts`: clean.
- `python -m build` and `twine check dist/*`: passed.
- `pip-audit`: no known vulnerabilities at build time.
- Live direct run in November 2026: 6 accounts, 522 transactions, 0 per-account
  errors, 0 duplicate transaction identifiers.
- Enable Banking live validation is still pending an Enable Banking
  application ID, RSA key and registered redirect URI.

## [0.1.0] - 2026-11-19

Initial pre-publication release of the Enable Banking backend. No live BNP
Paribas account had been used to validate this version yet.

### Added

- Standalone JSON CLI for BNP Paribas account information through Enable
  Banking PSD2/AIS: accounts, balances, transactions and full export.
- `auth setup`, `auth link`, `auth complete`, `auth status` and `auth logout`
  commands.
- `accounts`, `transactions`, `export` and `doctor` commands.
- RS256 JWT signed on the fly with the Enable Banking application ID as `kid`,
  `iss=enablebanking.com` and `aud=api.enablebanking.com`.
- Local loopback callback server with OAuth `state` validation, a minimal HTML
  response and a self-signed HTTPS certificate generated in `cache/`.
- Manual completion path (`auth link --no-wait`,
  `auth complete --callback-url-stdin`) for non-local redirect URIs.
- PSD2 consent lifetime capped at 180 days and reduced by a 60-second safety
  margin under the bank's advertised maximum.
- Transaction pagination until no `continuation_key` remains, with duplicate
  key and page-limit protection.
- `--from`, `--to`, `--pending`, `--status`, `--strategy`, `--max-pages` and
  `--limit` transaction filters.
- Booked balance selection (`CLBD` first) and available balance selection
  (`CLAV`, `ITAV`, `OPAV`).
- `DBIT` transactions negative, `CRDT` transactions positive, with `Decimal`
  parsing.
- Per-account error isolation and `status: "ok" | "partial"` exports.
- `export --output PATH` with atomic `0600` writes and a small receipt.
- `doctor` checks for Python, storage, configuration, private key, session,
  pending link and optional network/ASPSP access.
- Versioned JSON schemas and a stable `dedupKey` of the form
  `bnp:<accountUid>:<transactionId>`.
- `scripts/real_smoke.py` for manual validation with an existing session; it
  reports counters and dates, not balances or IBANs, unless `--show-data` is
  passed.

### Security

- **BNP Paribas password is never requested, stored, logged or transmitted.**
  Login and SCA happen in the browser on BNP Paribas' pages.
- Enable Banking private key stored separately from `config.json`, in a
  `0600` file, never serialized into configuration.
- PSD2 session treated as a bearer token and stored in `data/session.json`
  (`0600`).
- Private files opened with `O_NOFOLLOW`, checked as regular files, refused
  when group/other readable, capped at 64 KiB, and written atomically.
- Runtime directories created as `0700`; pre-existing directories are reported
  by `doctor` instead of being chmodded silently.
- `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME` and `XDG_CACHE_HOME` redirected
  into the private runtime directory while the CLI runs.
- OAuth `state` generated with 256 bits, compared in constant time, stored for
  at most 15 minutes.
- Authorization codes, JWTs, session IDs, application IDs, private-key lines
  and `code`/`state` parameters redacted from errors and debug traces.
- Fixed Enable Banking base URL; HTTP allowed only for loopback test servers.
- TLS verification enabled, HTTP redirects refused, responses capped at
  16 MiB, 30-second default timeout.
- Read-only endpoint allowlist; no payment initiation, transfer or write
  endpoint.
- CI workflow with tests on Python 3.11, 3.12 and 3.13, package build and
  `twine check`.

### Validation

- Automated suite: **107 tests**, no network access, using a fake Enable
  Banking client and a local fake HTTP server.
- `ruff check bnp_sidecar tests scripts`: clean.
- `python -m compileall -q bnp_sidecar tests scripts`: clean.
- `python -m build` and `twine check dist/*`: passed.
- `pip-audit`: no known vulnerabilities at build time.
- Real BNP Paribas validation was still pending an Enable Banking application
  ID, RSA key and registered redirect URI.

[0.2.0]: https://github.com/Romaindujardin/bnp-sidecar/releases/tag/v0.2.0
[0.1.0]: https://github.com/Romaindujardin/bnp-sidecar/releases/tag/v0.1.0

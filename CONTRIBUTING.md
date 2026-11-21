# Contributing

Thanks for considering a contribution. This project handles banking data and
Enable Banking credentials; security and predictability come first.

## Before you start

- Do not open a public issue for a security vulnerability. Follow
  [SECURITY.md](SECURITY.md).
- Do not paste real Enable Banking application IDs, private keys, session
  files, authorization codes, IBANs, balances or transaction labels into
  issues, pull requests or tests.
- Use synthetic data in tests and examples.
- The Enable Banking backend must **never** ask for or accept a BNP Paribas
  password, OTP code or SCA code. Authentication stays in the browser.
- The direct backend may prompt for the BNP customer ID and 6-digit code on a
  terminal, but never through `argv`, an environment variable, a configuration
  file, a log or a fixture. Direct session cookies and 2FA state must stay in
  memory.

## Development setup

```bash
git clone https://github.com/Romaindujardin/bnp-sidecar.git
cd bnp-sidecar
python3.11 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e ".[dev,direct]"
.venv/bin/pytest
uvx ruff check bnp_sidecar tests scripts
```

The automated suite must never contact Enable Banking or BNP Paribas. Use the
fake client in `tests/conftest.py`, the fake direct session in
`tests/test_direct_client.py`, or a local HTTP server bound to `127.0.0.1`.

## Coding guidelines

- Keep the JSON schemas stable. Add fields rather than renaming existing ones;
  document intentional changes in `docs/JSON-SCHEMAS.md`.
- Keep both clients read-only. Do not add payment initiation, transfers, orders
  or generic write endpoints. A new Enable Banking or direct endpoint needs a
  clear read-only justification and an entry in the relevant allowlist.
- Keep the Enable Banking API base URL fixed to
  `https://api.enablebanking.com`. Do not add a configuration option that can
  redirect JWTs or sessions to another host.
- Keep direct data requests on the `_endpoint_allowed()` allowlist and validate
  every redirect hop against the BNP host allowlist. Do not re-enable automatic
  redirects on data requests.
- Never put a private key, JWT, authorization code, session ID, OAuth `state`,
  BNP customer ID, 6-digit code, 2FA code or cookie in `argv`, logs, JSON
  output, tests or commit history.
- Route sensitive file access through `private_files.read_private_text()` or
  an equally strict helper. New private files must be written atomically with
  mode `0600`, and symlinks must be refused.
- Register new secrets with `redact.Redactor` and add a regression test.
- Keep the Enable Banking password boundary: do not add password, OTP or SCA
  prompts, options or environment variables to that backend.
- For direct mode, keep credential prompts on the terminal only. The 6-digit
  code must be converted to keyboard positions and the caller must discard the
  original reference. The optional 2FA structure file must never contain field
  values, codes, cookies or authorization headers.
- Validate callback `state` with `secrets.compare_digest` and keep the callback
  server bound to loopback.
- Prefer the standard library over new dependencies. A new dependency needs a
  clear reason, a security review and a deliberate version policy.
- Follow the existing formatting and naming style; the codebase targets Python
  3.11+.

## Tests

```bash
.venv/bin/pytest
.venv/bin/pytest -m "not real and not network"
```

Add regression tests for every security fix. Useful patterns:

- use `tmp_path` for private-file and permission tests;
- use `monkeypatch` for environment variables;
- use the local fake HTTP server in `tests/test_client.py` for transport
  behavior;
- use `FakeEnableBankingClient` for CLI flows;
- assert that secrets never appear in stdout, stderr, error details or
  JSON output.

The suite currently covers JWT signing, configuration, private files,
redaction, sessions, balances, transactions, pagination, callback validation,
the local certificate, the Enable Banking HTTP client, direct login/MFA
parsing, direct account/transaction parsing, direct redirect validation,
keyboard positions and end-to-end CLI commands.

## Real-account validation

### Enable Banking

Real validation is manual and requires:

1. an Enable Banking application ID and RSA private key;
2. a redirect URI registered in the Enable Banking dashboard;
3. explicit authorization by the account holder in the browser;
4. an existing session created with `bnp-sidecar auth link`.

Then run:

```bash
.venv/bin/python scripts/real_smoke.py
.venv/bin/python scripts/real_smoke.py --export
```

The script never prompts for a BNP password and never opens an authorization
flow. By default it prints counters, account types, dates and error codes, not
balances or IBANs. `--show-data` is intentionally more verbose.

### Direct

Use the direct commands with your own account:

```bash
.venv/bin/bnp-direct probe
.venv/bin/bnp-direct accounts --output /tmp/bnp-accounts.json
.venv/bin/bnp-direct export --since 2025-01-01 --output /tmp/bnp-export.json
```

The commands prompt on the terminal for the customer ID, 6-digit code and any
2FA code. Do not put these values in a script, shell history, CI job or issue.
Use `--output` so the export is written with mode `0600`, and delete the file
after reviewing it.

Never commit real output unless you have removed all account identifiers,
balances, IBANs, transaction data and local paths. Before pushing, check the
diff for:

- `config/config.json`, `config/private-key.pem`;
- `data/session.json`, `data/pending-link.json`, `data/mfa-structure.json`;
- `cache/callback-cert.pem`, `cache/callback-key.pem`;
- exported JSON, logs or `.env` files;
- real application IDs, customer IDs, redirect URIs or transaction labels.

Do not read credentials from another project (including Portfolio-Dashboard)
without explicit permission from their owner.

## Pull requests

- Keep the change focused.
- Describe the behavior change and its security impact.
- Mention the tests and checks you ran.
- Update `README.md`, `SECURITY.md`, `docs/SECURITY-AUDIT.md`,
  `docs/JSON-SCHEMAS.md` or `CHANGELOG.md` when relevant.
- Do not bump the version unless a maintainer asks; releases are tagged
  separately.
- Do not add generated build artifacts (`dist/`, `build/`, `.venv/`,
  `*.egg-info/`) to the repository.

## License

By contributing, you agree that your contribution is licensed under the MIT
License.

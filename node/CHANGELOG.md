# Changelog

## 0.3.0 — 2026-10-19

- `VAULT_ENV_ENABLED`: an explicit on/off switch. `false` / `0` / `no` / `off`: no request to Vault, one line on stderr (`VAULT_ENV_ENABLED is off; nothing loaded from Vault.`), the command runs, `load()` / `loadSync()` return `[]`, `fetch()` returns `{}`, `check` prints the same line and exits 0; the credentials are still removed from the application's environment as after a load (unless `VAULT_ENV_KEEP_TOKEN=true`), and `VAULT_ENV_LOADED` is not set. `true` / `1` / `yes` / `on`: Vault is required, so a missing `VAULT_ADDR` and `VAULT_ENV_IMPORT` fails with exit 78 instead of running without secrets. Any other value fails with exit 78. `VAULT_SKIP_VERIFY` is still refused first, whatever the switch says.
- Unset or empty: no change; behaviour, output and exit codes are those of 0.2.0.

## 0.2.0 — 2026-10-17

- AppRole authentication: `VAULT_ROLE_ID` / `VAULT_ROLE_ID_FILE`, `VAULT_SECRET_ID` / `VAULT_SECRET_ID_FILE`, `VAULT_ENV_APPROLE_MOUNT` (and `roleId`, `secretId`, `approleMount`, … in the library). Used only when no token is set: logs in once, reads, revokes the session with `auth/token/revoke-self`, then starts the command; the variables it used are removed from the command's environment.
- A login is retried only when Vault cannot have processed it (connection not established, 429, 503).
- No change when no AppRole variable is set: behaviour, output and exit codes are those of 0.1.1.

## 0.1.1 — 2026-10-15

- First release published from GitHub Actions with npm provenance (Trusted Publishing). No changes in behaviour.

## 0.1.0 — 2026-10-15

- First release: wrapper command, `-r` / `--import` preload, `load()` / `loadSync()` / `fetch()`, `check`.
- Spring Cloud Vault style imports with `optional:`, `prefix=`, `name=` and `kv=`; base path from `VAULT_ENV_BASE` or token metadata.
- KV v1 / v2 detection, retries for transient failures, exit code 78 on failure, `VAULT_TOKEN` removed from the application's environment.

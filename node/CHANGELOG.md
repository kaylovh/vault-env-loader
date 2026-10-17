# Changelog

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

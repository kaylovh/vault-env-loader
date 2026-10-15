# Changelog

## 0.1.1 — 2026-10-15

- First release published from GitHub Actions with npm provenance (Trusted Publishing). No changes in behaviour.

## 0.1.0 — 2026-10-15

- First release: wrapper command, `-r` / `--import` preload, `load()` / `loadSync()` / `fetch()`, `check`.
- Spring Cloud Vault style imports with `optional:`, `prefix=`, `name=` and `kv=`; base path from `VAULT_ENV_BASE` or token metadata.
- KV v1 / v2 detection, retries for transient failures, exit code 78 on failure, `VAULT_TOKEN` removed from the application's environment.

# Changelog

## 0.1.0 — 2026-10-15

- First release, with the same configuration and behaviour as the Node.js package: wrapper command (exec on POSIX), `python -m vault_env_loader`, `load()` / `fetch()`, `check`.
- Spring Cloud Vault style imports with `optional:`, `prefix=`, `name=` and `kv=`; base path from `VAULT_ENV_BASE` or token metadata.
- KV v1 / v2 detection, retries for transient failures, exit code 78 on failure, `VAULT_TOKEN` removed from the application's environment.
- Redirects are not followed, so the token is only sent to `VAULT_ADDR`. Honours `HTTPS_PROXY` / `NO_PROXY`.
- Python 3.6 to 3.14, Linux, macOS and Windows.

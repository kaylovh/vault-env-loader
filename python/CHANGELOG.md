# Changelog

## 0.4.0 — 2026-11-23

- Certificate login: with `VAULT_ROLE_ID` (or `_FILE`) and `VAULT_CLIENT_CERTIFICATE_PATH` (one PEM file with the private key and the certificate; optional `VAULT_CLIENT_KEY_PATH`, `VAULT_CLIENT_CERTIFICATE_PASSWORD` / `_PASSWORD_FILE`, `VAULT_ENV_JWT_MOUNT`, default `jwt`), it signs a 120-second JWT client assertion (RS256, ES256 or ES384; `x5t#S256`; `iss` = `sub` = the role ID; `aud` = `VAULT_ADDR` + `/v1/auth/<mount>/login`; a random `jti`) and logs in with `POST auth/<mount>/login {role, jwt}`, then reads and revokes the session as with AppRole. Flags `--client-certificate-path`, `--client-key-path`, `--jwt-mount`; there is no password flag. Works with a plain Vault JWT auth method (`jwt_validation_pubkeys`).
- A secret ID together with a certificate, or a certificate without a role ID, is a configuration error (exit 78). A bad certificate or key file (unreadable, not PEM, wrong password, key not matching) fails with exit 78 before any request.
- A certificate login is retried on connection errors, timeouts, 429 and 5xx, each time with a new assertion; 400 / 403 fail at once with exit 78 and without the server's text.
- Only the certificate variables that were used are removed from the command's environment; the files are never touched.
- `check` shows the certificate's thumbprint prefix and expiry; fewer than 30 days left gives a warning on every run.
- `client_assertion(role_id=, certificate_path=, key_path=None, password=None, vault_addr=, mount="jwt")`: the same signed JWT for other clients (hvac `jwt_login`).
- The certificate method needs the new `[cert]` extra (`pip install "vault-env-loader[cert]"`, `cryptography>=3.4`), imported only when that method is chosen; without it, exit 78 with the install command. The base package keeps zero dependencies and Python >= 3.6.
- No change without `VAULT_CLIENT_CERTIFICATE_PATH`: behaviour, output and exit codes are those of 0.3.0.

## 0.3.0 — 2026-10-19

- `VAULT_ENV_ENABLED`: an explicit on/off switch. `false` / `0` / `no` / `off`: no request to Vault, one line on stderr (`VAULT_ENV_ENABLED is off; nothing loaded from Vault.`), the command runs, `load()` returns `[]`, `fetch()` returns `{}`, `check` prints the same line and exits 0; the credentials are still removed from the application's environment as after a load (unless `VAULT_ENV_KEEP_TOKEN=true`), and `VAULT_ENV_LOADED` is not set. `true` / `1` / `yes` / `on`: Vault is required, so a missing `VAULT_ADDR` and `VAULT_ENV_IMPORT` fails with exit 78 instead of running without secrets. Any other value fails with exit 78. `VAULT_SKIP_VERIFY` is still refused first, whatever the switch says.
- Unset or empty: no change; behaviour, output and exit codes are those of 0.2.0.

## 0.2.0 — 2026-10-17

- AppRole authentication: `VAULT_ROLE_ID` / `VAULT_ROLE_ID_FILE`, `VAULT_SECRET_ID` / `VAULT_SECRET_ID_FILE`, `VAULT_ENV_APPROLE_MOUNT` (and `role_id`, `secret_id`, `approle_mount`, … as keyword options). Used only when no token is set: logs in once, reads, revokes the session with `auth/token/revoke-self`, then starts the command; the variables it used are removed from the command's environment.
- A login is retried only when Vault cannot have processed it (request never sent, 429, 503).
- No change when no AppRole variable is set: behaviour, output and exit codes are those of 0.1.0.

## 0.1.0 — 2026-10-15

- First release, with the same configuration and behaviour as the Node.js package: wrapper command (exec on POSIX), `python -m vault_env_loader`, `load()` / `fetch()`, `check`.
- Spring Cloud Vault style imports with `optional:`, `prefix=`, `name=` and `kv=`; base path from `VAULT_ENV_BASE` or token metadata.
- KV v1 / v2 detection, retries for transient failures, exit code 78 on failure, `VAULT_TOKEN` removed from the application's environment.
- Redirects are not followed, so the token is only sent to `VAULT_ADDR`. Honours `HTTPS_PROXY` / `NO_PROXY`.
- Python 3.6 to 3.14, Linux, macOS and Windows.

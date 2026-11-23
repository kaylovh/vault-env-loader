# vault-env-loader (Python)

Load secrets from HashiCorp Vault's KV engine into environment variables **before your application starts**. Your code keeps reading `os.environ` / `os.getenv` — Django settings, Flask config, pydantic `BaseSettings`, `django-environ`, `python-decouple` all keep working — and the `.env` file full of plaintext passwords can go.

- **Zero dependencies.** One file, standard library only, Python ≥ 3.6. Old projects with pinned `requests` versions are not affected.
- **Fails fast.** If a secret cannot be loaded, your application does not start (exit code 78), instead of failing later in business code.
- **Imports like Spring Cloud Vault.** `vault://secret/my-app/prod/database`.
- **The token stays out of your app.** `VAULT_TOKEN` is removed from the environment your application sees.
- **Token, AppRole or a certificate.** With AppRole (a secret ID or a [certificate](#certificate-login)) it logs in once per start, reads, and revokes the session before your app runs.
- Works with HashiCorp Vault (KV v1 and v2, auto-detected) and with Vault-compatible servers.
- Same configuration and behaviour as the [Node.js package](https://github.com/kaylovh/vault-env-loader/tree/main/node).

## Quick start

```bash
pip install vault-env-loader
```

Configure it where you deploy (instead of putting secrets in `.env`):

```bash
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=hvs.xxxxx                     # or VAULT_TOKEN_FILE=/run/secrets/vault-token
VAULT_ENV_IMPORT="vault://secret/order-service/prod/database, vault://secret/order-service/prod/redis?prefix=REDIS_"
```

Then pick **one** way to hook it in.

### A. Wrap the start command (recommended — no code change)

```bash
vault-env-loader -- gunicorn app.wsgi
vault-env-loader -- uvicorn app.main:app --host 0.0.0.0
vault-env-loader -- celery -A proj worker
vault-env-loader -- python manage.py migrate
python -m vault_env_loader -- python app.py      # when the scripts directory is not on PATH
```

```dockerfile
ENTRYPOINT ["vault-env-loader", "--"]
CMD ["gunicorn", "app.wsgi", "--bind", "0.0.0.0:8000"]
```

Works for anything: systemd, supervisor, cron, shell scripts — the wrapped program does not even have to be Python. On Linux and macOS the wrapper **replaces itself** with your command (`exec`): same PID, signals and exit code need no forwarding, and PID 1 in a container is your application.

### B. One line at the top of your entry file

```python
import vault_env_loader; vault_env_loader.load()   # must run before anything reads the configuration
```

Where "the top" is:

| Framework | Put it at the top of |
|---|---|
| Django | `manage.py`, `wsgi.py` and `asgi.py` (before `django` is imported), or the first line of `settings.py` |
| Flask / FastAPI | the module that creates the app, before the config is read |
| Celery | the module that creates the `Celery()` app |
| python-dotenv | **before** `load_dotenv()` |

`load()` blocks until every import is loaded, writes `os.environ`, removes `VAULT_TOKEN`, and returns the names it set. It does nothing if the environment was already loaded (for example by the wrapper, or in a reloader's child process).

### C. Just get the values

```python
from vault_env_loader import fetch
values = fetch()          # {'DB_PASSWORD': '...', ...}; os.environ is not touched
```

## Configuration

Connection settings use Vault's standard variable names, so the `vault` CLI, `hvac` and other clients share them. Options of this tool start with `VAULT_ENV_`. Command-line flags of the same name take precedence.

| Variable | Flag | Meaning |
|---|---|---|
| `VAULT_ADDR` | `--addr` | Vault address. Required. |
| `VAULT_TOKEN` | — | Token. There is deliberately no `--token` flag: arguments are visible in `ps`. |
| `VAULT_TOKEN_FILE` | `--token-file` | Read the token from a file instead. |
| `VAULT_ROLE_ID` / `VAULT_ROLE_ID_FILE` | `--role-id-file` | [AppRole](#approle) role ID, used only when no token is set. |
| `VAULT_SECRET_ID` / `VAULT_SECRET_ID_FILE` | `--secret-id-file` | AppRole secret ID. There is no `--secret-id` flag, for the same reason as `--token`. |
| `VAULT_ENV_APPROLE_MOUNT` | `--approle-mount` | AppRole auth mount. Default `approle`. |
| `VAULT_CLIENT_CERTIFICATE_PATH`, `VAULT_CLIENT_KEY_PATH`, `VAULT_CLIENT_CERTIFICATE_PASSWORD(_FILE)`, `VAULT_ENV_JWT_MOUNT` | see [Certificate login](#certificate-login) | Log in with the role ID and a certificate instead of a secret ID. |
| `VAULT_NAMESPACE` | — | Vault Enterprise namespace. |
| `VAULT_CACERT` / `VAULT_CAPATH` | — | Extra CA certificate file / directory (every `*.pem` and `*.crt` in it). The system trust store is always used too. |
| `VAULT_ENV_IMPORT` | `--import` | What to load, comma or newline separated (flag repeatable). Required. |
| `VAULT_ENV_BASE` | `--base` | Base path for relative imports. |
| `VAULT_ENV_OVERRIDE` | `--override` | `true`: replace variables that are already set. Default: keep them. |
| `VAULT_ENV_KEEP_TOKEN` | `--keep-token` | `true`: leave `VAULT_TOKEN` (or the AppRole / certificate variables) in the application's environment. |
| `VAULT_ENV_TIMEOUT` | `--timeout` | Seconds per request. Default 10. |
| `VAULT_ENV_RETRIES` | `--retries` | Retries for transient failures. Default 3 (1 s, 2 s, 4 s). |
| `VAULT_ENV_ALLOW_HTTP` | — | `true` to allow plain `http://` to a host other than localhost. Prints a warning on every start. |
| `VAULT_ENV_ENABLED` | — | `false`: load nothing and run the application without Vault; `true`: Vault is required. Unset: as below. See [Switching it off](#switching-it-off-vault_env_enabled). |

**TLS verification cannot be turned off.** If `VAULT_SKIP_VERIFY` is set, vault-env-loader stops with an error rather than silently ignoring it. Point `VAULT_CACERT` at your CA instead.

**Proxies:** like every Python HTTP client, requests honour `HTTPS_PROXY` / `HTTP_PROXY` and `NO_PROXY`. Servers often set a global proxy for `pip`; if Vault is reachable directly, add its host to `NO_PROXY`. (The Node.js package does not use proxies.)

If neither `VAULT_ADDR` nor `VAULT_ENV_IMPORT` is set, nothing is loaded and the command runs anyway — the same start command works on a laptop without Vault. Setting only some of them is an error.

### Switching it off: `VAULT_ENV_ENABLED`

An explicit switch, for a rollback window while the old values are still in place, for local development that keeps the Vault settings in `.env` but must not use them, or for a single run: `VAULT_ENV_ENABLED=false vault-env-loader -- gunicorn app.wsgi`. It is not a fallback for a Vault outage: switched off, the application only has what is already in its environment.

| Value (case and surrounding spaces ignored) | Behaviour |
|---|---|
| unset or empty | As described above. |
| `false`, `0`, `no`, `off` | Nothing is read from Vault, no request is made and no other setting is checked. One line on stderr, `[vault-env-loader] VAULT_ENV_ENABLED is off; nothing loaded from Vault.`, then the command runs (exit code passed through); `load()` returns `[]` and `fetch()` returns `{}`. The credentials are still removed from the application's environment, exactly as after a load (unless `VAULT_ENV_KEEP_TOKEN=true`): `VAULT_TOKEN`; `VAULT_TOKEN_FILE` when the token would come from that file; without a token, `VAULT_ROLE_ID` (or else `VAULT_ROLE_ID_FILE`) and `VAULT_SECRET_ID` (or else `VAULT_SECRET_ID_FILE`). `VAULT_ENV_LOADED` is not set. |
| `true`, `1`, `yes`, `on` | Vault is required. If neither `VAULT_ADDR` nor `VAULT_ENV_IMPORT` is set, it fails with exit 78 and `VAULT_ENV_ENABLED is on, but VAULT_ADDR and VAULT_ENV_IMPORT are not set.` instead of running without secrets. Otherwise as usual. |
| anything else | Fails with exit 78: `VAULT_ENV_ENABLED must be true or false (or 1/0, yes/no, on/off).` |

Switched off, `check` prints `VAULT_ENV_ENABLED is off; nothing loaded from Vault.` and exits 0. `VAULT_SKIP_VERIFY` is refused whatever the switch says. Because `VAULT_ENV_LOADED` is not set, a child process that calls `load()` again prints the line again.

## AppRole

When no token is configured and `VAULT_ROLE_ID` (or `VAULT_ROLE_ID_FILE`) is, vault-env-loader authenticates with [AppRole](https://developer.hashicorp.com/vault/docs/auth/approle):

```bash
VAULT_ADDR=https://vault.example.com
VAULT_ROLE_ID=59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8
VAULT_SECRET_ID_FILE=/run/secrets/vault-secret-id   # or VAULT_SECRET_ID=...
VAULT_ENV_BASE=secret/order-service/prod            # see below
VAULT_ENV_IMPORT="database, redis?prefix=REDIS_"
```

1. `POST auth/approle/login` (or `auth/<VAULT_ENV_APPROLE_MOUNT>/login`) with the role ID and, if set, the secret ID;
2. the imports are read with the session token it returns;
3. `auth/token/revoke-self` revokes the session — also when a read failed. If the revoke fails, a warning is printed and the session simply expires;
4. your command starts (on POSIX the wrapper `exec`s it, after the revoke). The session token never enters its environment, and the AppRole variables that were used are removed (unless `VAULT_ENV_KEEP_TOKEN=true`, which leaves them so the application can log in itself).

Things to know:

- **A token wins.** If `VAULT_TOKEN` or `VAULT_TOKEN_FILE` is set, it is used exactly as before and the AppRole variables are left untouched (a note says so).
- **Every start uses the secret ID once**, and so does `check`. A secret ID limited to a number of uses (`secret_id_num_uses`) suits one-off jobs; a service that restarts needs an unlimited one.
- **The policy needs** `read` on the paths, and the `default` policy (for `lookup-self` and `revoke-self`) — AppRole tokens get it unless the role sets `token_no_default_policy`.
- **Relative imports** need a base path. AppRole tokens usually carry only `role_name` as metadata, so set `VAULT_ENV_BASE`, or write absolute `vault://` paths. A server that puts `application` and `environment` in the session's metadata gets the base from there, as with tokens.
- **The login is not repeated once it was sent.** Connection failures before that, 429 and 503 are retried; a timeout or 5xx after the request went out is not, because Vault may already have used up a secret ID use.
- Response wrapping (`secret_id` delivered as a wrapping token) is not supported.

## Certificate login

Instead of a secret ID, a role can log in with a **certificate**, like an Azure app registration's certificate credential: the application signs a short-lived JWT (a *client assertion*) with its private key, and Vault checks it against the public key it trusts. The private key never leaves the application, and nothing that crosses the network can be replayed.

```bash
pip install "vault-env-loader[cert]"      # the certificate method needs cryptography >= 3.4
```

```bash
VAULT_ADDR=https://vault.example.com
VAULT_ROLE_ID=59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8
VAULT_CLIENT_CERTIFICATE_PATH=/run/secrets/vault/app.pem   # one PEM file: private key and certificate
VAULT_ENV_IMPORT="vault://secret/order-service/prod/database"
```

| Variable | Flag | Meaning |
|---|---|---|
| `VAULT_CLIENT_CERTIFICATE_PATH` | `--client-certificate-path` | PEM file with the certificate (the first `BEGIN CERTIFICATE` block) and, unless the next variable is set, the private key. Any path you like; `~` is not expanded. |
| `VAULT_CLIENT_KEY_PATH` | `--client-key-path` | The private key, when it is in a file of its own. |
| `VAULT_CLIENT_CERTIFICATE_PASSWORD` / `VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE` | — | Password of an encrypted key (`ENCRYPTED PRIVATE KEY`). Taken as it is; the file loses one trailing line break. No flag, for the same reason as `--token`. |
| `VAULT_ENV_JWT_MOUNT` | `--jwt-mount` | JWT auth mount. Default `jwt`. |

Keys: RSA (signed RS256), EC P-256 (ES256) or EC P-384 (ES384), PEM only (PKCS#8, PKCS#1 or SEC 1). PKCS#12 / PFX files are not read: `openssl pkcs12 -in app.pfx -out app.pem` converts one.

Which method is used:

1. `VAULT_TOKEN` or `VAULT_TOKEN_FILE` set → the token, as before; the other variables are left alone (a note says so).
2. A role ID and `VAULT_CLIENT_CERTIFICATE_PATH` → certificate login. A secret ID as well is a configuration error (exit 78): one or the other.
3. `VAULT_CLIENT_CERTIFICATE_PATH` without a role ID → configuration error (exit 78).
4. Otherwise, as in 0.3 (AppRole with a secret ID, or a token). A key path or password without a certificate path changes nothing.

What happens:

1. The certificate and key are read and checked (readable, PEM, the key belongs to the certificate, the password is right). Any problem fails with exit 78 **before any request**.
2. A JWT is signed: header `alg`, `typ: JWT`, `x5t#S256` (base64url SHA-256 of the certificate); claims `iss` = `sub` = the role ID, `aud` = `VAULT_ADDR` + `/v1/auth/<mount>/login` (scheme and host in lower case, no default port, no trailing `/`), `iat`, `exp` = `iat` + 120 s, and a random 128-bit `jti`.
3. `POST auth/<mount>/login` with `{"role": <role ID>, "jwt": <JWT>}`, then the imports are read with the session token, then `auth/token/revoke-self`, then your command starts — exactly as with AppRole. The session token never reaches your command or the disk, and only the variables that were used are removed from its environment (unless `VAULT_ENV_KEEP_TOKEN=true`). The files are never touched.

Things to know:

- **Retries are safe.** A certificate can log in any number of times, so connection failures, timeouts, 429 and 5xx are retried (`VAULT_ENV_RETRIES`), each time with a new assertion. A 400 / 403 is not: exit 78, `Certificate login failed: the role ID or certificate is not accepted (mount jwt).` — the server's own text is never printed.
- **Expiry.** `check` shows the certificate and when it expires: `auth     certificate (role_id 59d6d1ca..., cert q3Z1Ab12..., expires 2028-11-20, 728 days, mount jwt; session revoked after reading)`. With fewer than 30 days left, every run warns. An expired certificate is still sent (a plain Vault JWT role does not look at it) with a warning.
- **Whoever can read the key file can log in.** Mount it with tight permissions, like any secret.
- **Python: the `[cert]` extra.** Signing uses the [`cryptography`](https://pypi.org/project/cryptography/) package, imported only when this method is chosen; the base package stays dependency-free. Without it the wrapper exits 78 with the install command. On Python 3.6 and 3.7, pip installs an old `cryptography` that no longer gets security fixes: use Python 3.8 or later for this method if you can.

### With HashiCorp Vault

vault-env-loader sends the role ID as the JWT role's name, so name the role after it. A JWT auth method that trusts your certificate's public key:

```bash
vault auth enable jwt
openssl x509 -in app.pem -pubkey -noout > app.pub
vault write auth/jwt/config jwt_validation_pubkeys=@app.pub jwt_supported_algs=RS256,ES256,ES384
vault write auth/jwt/role/order-service-prod role_type=jwt user_claim=sub \
    bound_subject=order-service-prod bound_audiences=https://vault.example.com/v1/auth/jwt/login \
    token_policies=order-service-prod token_ttl=10m
# then VAULT_ROLE_ID=order-service-prod
```

Such a token carries only `role` as metadata, so set `VAULT_ENV_BASE` or write absolute `vault://` paths for the imports.

### Other Vault clients

Libraries that log in with a JWT but cannot sign one can use the same assertion:

```python
import hvac
from vault_env_loader import client_assertion

jwt = client_assertion(role_id=ROLE_ID, certificate_path="/run/secrets/vault/app.pem", vault_addr=VAULT_ADDR)
client = hvac.Client(url=VAULT_ADDR)
client.auth.jwt.jwt_login(role=ROLE_ID, jwt=jwt)
```

`client_assertion(role_id=, certificate_path=, key_path=None, password=None, vault_addr=, mount="jwt")` returns the signed JWT (valid 120 s, a new `jti` each call) and raises `VaultEnvError` for a file it cannot use. hvac does not renew or log in again by itself: on a 403, sign a new assertion and log in again; that costs nothing.

## Imports

```
[optional:]<location>[?prefix=<PREFIX>&name=auto|verbatim|upper&kv=1|2]

location:  vault://<mount>/<path>    absolute, as in Spring Cloud Vault
           <path>                    relative to the base path
           vault://                  the base path itself
```

- **`optional:`** — skip the import if the path does not exist. Permission errors and outages still fail.
- **`prefix=`** — prepend to every variable name from this import.
- **`kv=`** — the KV engine version. Without it, vault-env-loader asks Vault (`sys/internal/ui/mounts`, like `vault kv get` does); the token's policy needs `read` on `sys/internal/ui/mounts/*` for that, otherwise version 2 is assumed.
- When several imports set the same variable, **the later one wins** (with a warning).

### Relative imports and the base path

The base path is taken from, in order:

1. `VAULT_ENV_BASE` (e.g. `secret/order-service/prod`);
2. the token's metadata: if it has both `application` and `environment`, the base is `secret/<application>/<environment>`. Create such a token with `vault token create -policy=... -metadata=application=order-service -metadata=environment=prod`.

With a token-derived base, every environment uses **the same** `VAULT_ENV_IMPORT="database, redis"` and only the token differs.

## Variable names

Vault keys may contain characters that are not valid in environment variable names (`db.password`, `spring.datasource.url`). The `name=` option decides:

| `name=` | Rule | `DB_PASSWORD` | `db.password` | `spring.datasource.url` | `database_url` |
|---|---|---|---|---|---|
| `auto` (default) | Valid names unchanged; others upper-cased with invalid characters → `_` | `DB_PASSWORD` | `DB_PASSWORD` | `SPRING_DATASOURCE_URL` | `database_url` |
| `verbatim` | Unchanged (`os.environ['db.password']` works; shells cannot use it) | `DB_PASSWORD` | `db.password` | `spring.datasource.url` | `database_url` |
| `upper` | Always upper-cased, invalid characters → `_` | `DB_PASSWORD` | `DB_PASSWORD` | `SPRING_DATASOURCE_URL` | `DATABASE_URL` |

If two keys of one import map to the same name (`db.password` and `db-password`), loading **fails** and names both keys — order never silently decides. On Windows, names are compared case-insensitively. Non-string values (Vault allows JSON) are injected as compact JSON text.

## Precedence

Variables that already exist in the environment **win** by default — the same rule as python-dotenv and Spring. That lets you override a value locally, and it means `load_dotenv()` called *after* vault-env-loader cannot overwrite Vault's values (unless you pass `override=True`), so a stale `.env` can stay in place until you have verified the migration. vault-env-loader prints the names (never the values) of variables it left alone. `VAULT_ENV_OVERRIDE=true` reverses this.

## Checking a configuration

```bash
vault-env-loader check
```

prints the token's expiry and metadata, the path and version each import resolved to, and the variables that would be set — **names and lengths only, never values**.

## Failures

Nothing is started unless every non-optional import loads. The process exits with **78** (`EX_CONFIG`) and one line on stderr; `load()` and `fetch()` raise `VaultEnvError`.

| Situation | Retried? |
|---|---|
| 401 / 403 — invalid, expired or revoked token, or the policy does not allow the path | no |
| AppRole login 400 / 403 — wrong, expired or used-up role ID / secret ID | no |
| AppRole login: connection not established, 429, 503 | yes |
| AppRole login: timeout, connection lost or 5xx after the request was sent | no |
| Certificate login 400 / 401 / 403 — role ID or certificate not accepted | no |
| Certificate login: connection errors, timeouts, 429, 5xx (a new assertion each time) | yes |
| Certificate or key file unreadable, not PEM, wrong password, key not matching | no — fails before any request |
| 404 — path does not exist (skipped if `optional:`) | no |
| 429, 500, 502, 503, 504, connection errors, timeouts | yes, `VAULT_ENV_RETRIES` times — except a 502 that names keys with a permanent reason (e.g. `alias 'x' could not be resolved: not_found`), which fails at once |
| 3xx redirects | not followed (the token would go with them); fails |

A token that expires within 14 days produces a warning (not an AppRole session: those are short-lived by design).

## Things to know

- **Rotation needs a restart.** Values are read once, at start — just like editing `.env`. `check` shows each path's version so you can tell whether a restart is due.
- **gunicorn / uwsgi / celery** — with the wrapper, the master loads once and workers inherit the environment. With `load()`, put it where the master imports it (e.g. `gunicorn.conf.py`, or use `--preload`) so that workers do not each read Vault.
- **Reloaders** (`runserver`, `uvicorn --reload`) start children with the loaded environment and `VAULT_ENV_LOADED`, so they do not read again. Restart the outer command to pick up new values.
- **One value is limited to 128 KB** (the Linux limit for one environment string); larger values are refused with the key name.
- **No `.pth` auto-loading.** Loading on every interpreter start (including `pip`) would be invisible and fragile; the wrapper already needs no code change.
- **Windows** has no `exec`: the wrapper runs the command as a child and passes its exit code through.
- Token, AppRole (secret ID or certificate) authentication; Kubernetes auth may follow.

## Library API

```python
from vault_env_loader import load, fetch, client_assertion, VaultEnvError

load(env=None, **options)    # -> names set in os.environ (or in the mapping `env`)
fetch(env=None, **options)   # -> {NAME: value}; does not touch the environment
client_assertion(role_id=..., certificate_path=..., vault_addr=...)   # -> a signed JWT for auth/jwt/login ([cert] extra)
```

`options` mirror the variables above: `addr`, `token`, `token_file`, `role_id`, `role_id_file`, `secret_id`, `secret_id_file`, `approle_mount`, `client_certificate_path`, `client_key_path`, `client_certificate_password`, `client_certificate_password_file`, `jwt_mount`, `imports`, `base`, `namespace`, `cacert`, `capath`, `override`, `keep_token`, `timeout`, `retries`, `allow_http`. `env` is the mapping configuration is read from (and, for `load()`, written to); default `os.environ`. `VaultEnvError` has a `code`: `config`, `auth`, `not_found`, `resolve`, `collision`, `value`, `unavailable`. Messages contain paths and key names, never values or tokens.

## Security notes

- Secret values are never written to logs, error messages, argv or disk. Unexpected errors print only the exception type, never a traceback.
- Redirects are not followed, so the token (and the AppRole login) is only ever sent to `VAULT_ADDR`.
- The AppRole login body is never logged; `check` shows only the first 8 characters of the role ID.
- Certificate login: the private key is only read, never sent, logged or copied; the signed assertion (valid 120 s, single-use `jti`) is the only thing that leaves the process, and it is never logged. Error messages name the files, never their contents.
- Requests carry `User-Agent: vault-env-loader/<version> python/<version>`, so server audit logs can tell which client read what.

## License

MIT

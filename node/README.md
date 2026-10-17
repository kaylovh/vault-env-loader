# vault-env-loader (Node.js)

Load secrets from HashiCorp Vault's KV engine into environment variables **before your application starts**. Your code keeps reading `process.env` — nothing else changes, and the `.env` file full of plaintext passwords can go.

- **Zero dependencies.** One file, Node ≥ 14.
- **Fails fast.** If a secret cannot be loaded, your application does not start (exit code 78), instead of failing later in business code.
- **Imports like Spring Cloud Vault.** `vault://secret/my-app/prod/database`.
- **The token stays out of your app.** `VAULT_TOKEN` is removed from the environment your application sees.
- **Token or AppRole.** With AppRole it logs in once per start, reads, and revokes the session before your app runs.
- Works with HashiCorp Vault (KV v1 and v2, auto-detected) and with Vault-compatible servers.

## Quick start

```bash
npm install vault-env-loader
```

Configure it where you deploy (instead of putting secrets in `.env`):

```bash
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=hvs.xxxxx                     # or VAULT_TOKEN_FILE=/run/secrets/vault-token
VAULT_ENV_IMPORT="vault://secret/order-service/prod/database, vault://secret/order-service/prod/redis?prefix=REDIS_"
```

Then pick **one** way to hook it in.

### A. Wrap the start command (recommended — no code change)

```json
{ "scripts": { "start": "vault-env-loader -- node server.js" } }
```

Works for anything: `npm start`, a Dockerfile `ENTRYPOINT ["npx", "vault-env-loader", "--"]`, systemd, supervisor, shell scripts. The wrapped program does not even have to be Node. Signals are forwarded and the exit code is passed through.

### B. Preload (no code change)

```bash
node -r vault-env-loader/register server.js           # CommonJS
node --import vault-env-loader/register server.mjs    # ES modules, Node ≥ 18.19 / 20.6
NODE_OPTIONS="-r vault-env-loader/register" npm start # when you can only set variables (pm2, PaaS)
```

### C. One line at the top of your entry file (CommonJS)

```js
require('vault-env-loader').loadSync();   // must be the FIRST line
require('dotenv').config();               // if you use dotenv, AFTER this line
```

Two rules for C:

1. It must run **before** anything reads `process.env` — and before `dotenv`. Variables that already exist win by default, so if dotenv runs first and `.env` still holds an old password, the old one is used.
2. **Not for ES modules.** `import` statements are hoisted, so a line in your source cannot reliably run first. Use A or B, or a two-line bootstrap:

   ```js
   // boot.mjs — run `node boot.mjs`
   await (await import('vault-env-loader')).load();
   await import('./server.mjs');
   ```

## Configuration

Connection settings use Vault's standard variable names, so the `vault` CLI and other clients share them. Options of this tool start with `VAULT_ENV_`. Command-line flags of the same name take precedence.

| Variable | Flag | Meaning |
|---|---|---|
| `VAULT_ADDR` | `--addr` | Vault address. Required. |
| `VAULT_TOKEN` | — | Token. There is deliberately no `--token` flag: arguments are visible in `ps`. |
| `VAULT_TOKEN_FILE` | `--token-file` | Read the token from a file instead. |
| `VAULT_ROLE_ID` / `VAULT_ROLE_ID_FILE` | `--role-id-file` | [AppRole](#approle) role ID, used only when no token is set. |
| `VAULT_SECRET_ID` / `VAULT_SECRET_ID_FILE` | `--secret-id-file` | AppRole secret ID. There is no `--secret-id` flag, for the same reason as `--token`. |
| `VAULT_ENV_APPROLE_MOUNT` | `--approle-mount` | AppRole auth mount. Default `approle`. |
| `VAULT_NAMESPACE` | — | Vault Enterprise namespace. |
| `VAULT_CACERT` / `VAULT_CAPATH` | — | Extra CA certificate file / directory. `NODE_EXTRA_CA_CERTS` also works. |
| `VAULT_ENV_IMPORT` | `--import` | What to load, comma or newline separated (flag repeatable). Required. |
| `VAULT_ENV_BASE` | `--base` | Base path for relative imports. |
| `VAULT_ENV_OVERRIDE` | `--override` | `true`: replace variables that are already set. Default: keep them. |
| `VAULT_ENV_KEEP_TOKEN` | `--keep-token` | `true`: leave `VAULT_TOKEN` (or the AppRole variables) in the application's environment. |
| `VAULT_ENV_TIMEOUT` | `--timeout` | Seconds per request. Default 10. |
| `VAULT_ENV_RETRIES` | `--retries` | Retries for transient failures. Default 3 (1 s, 2 s, 4 s). |
| `VAULT_ENV_ALLOW_HTTP` | — | `true` to allow plain `http://` to a host other than localhost. Prints a warning on every start. |

**TLS verification cannot be turned off.** If `VAULT_SKIP_VERIFY` is set, vault-env-loader stops with an error rather than silently ignoring it. Point `VAULT_CACERT` at your CA instead.

If neither `VAULT_ADDR` nor `VAULT_ENV_IMPORT` is set, nothing is loaded and the command runs anyway — the same start command works on a laptop without Vault. Setting only some of them is an error.

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
4. your command starts. The session token never enters its environment, and the AppRole variables that were used are removed (unless `VAULT_ENV_KEEP_TOKEN=true`, which leaves them so the application can log in itself).

Things to know:

- **A token wins.** If `VAULT_TOKEN` or `VAULT_TOKEN_FILE` is set, it is used exactly as before and the AppRole variables are left untouched (a note says so).
- **Every start uses the secret ID once**, and so does `check`. A secret ID limited to a number of uses (`secret_id_num_uses`) suits one-off jobs; a service that restarts needs an unlimited one.
- **The policy needs** `read` on the paths, and the `default` policy (for `lookup-self` and `revoke-self`) — AppRole tokens get it unless the role sets `token_no_default_policy`.
- **Relative imports** need a base path. AppRole tokens usually carry only `role_name` as metadata, so set `VAULT_ENV_BASE`, or write absolute `vault://` paths. A server that puts `application` and `environment` in the session's metadata gets the base from there, as with tokens.
- **The login is not repeated once it was sent.** Connection failures before that, 429 and 503 are retried; a timeout or 5xx after the request went out is not, because Vault may already have used up a secret ID use.
- Response wrapping (`secret_id` delivered as a wrapping token) is not supported.

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
| `verbatim` | Unchanged (`process.env['db.password']` works; shells cannot use it) | `DB_PASSWORD` | `db.password` | `spring.datasource.url` | `database_url` |
| `upper` | Always upper-cased, invalid characters → `_` | `DB_PASSWORD` | `DB_PASSWORD` | `SPRING_DATASOURCE_URL` | `DATABASE_URL` |

If two keys of one import map to the same name (`db.password` and `db-password`), loading **fails** and names both keys — order never silently decides. On Windows, names are compared case-insensitively. Non-string values (Vault allows JSON) are injected as JSON text.

## Precedence

Variables that already exist in the environment **win** by default — the same rule as dotenv and Spring. That lets you override a value locally, and it means a `.env` loaded *after* vault-env-loader cannot overwrite Vault's values. vault-env-loader prints the names (never the values) of variables it left alone. `VAULT_ENV_OVERRIDE=true` reverses this.

## Checking a configuration

```bash
vault-env-loader check
```

prints the token's expiry and metadata, the path and version each import resolved to, and the variables that would be set — **names and lengths only, never values**.

## Failures

Nothing is started unless every non-optional import loads. The process exits with **78** (`EX_CONFIG`) and one line on stderr.

| Situation | Retried? |
|---|---|
| 401 / 403 — invalid, expired or revoked token, or the policy does not allow the path | no |
| AppRole login 400 / 403 — wrong, expired or used-up role ID / secret ID | no |
| AppRole login: connection not established, 429, 503 | yes |
| AppRole login: timeout, connection lost or 5xx after the request was sent | no |
| 404 — path does not exist (skipped if `optional:`) | no |
| 429, 500, 502, 503, 504, connection errors, timeouts | yes, `VAULT_ENV_RETRIES` times — except a 502 that names keys with a permanent reason (e.g. `alias 'x' could not be resolved: not_found`), which fails at once |

A token that expires within 14 days produces a warning (not an AppRole session: those are short-lived by design).

## Things to know

- **Rotation needs a restart.** Values are read once, at start — just like editing `.env`. `check` shows each path's version so you can tell whether a restart is due.
- **Build-time variables are out of scope.** `NEXT_PUBLIC_*`, Vite's `import.meta.env`, `REACT_APP_*` are inlined at build time; injecting them at run time has no effect (and they should not hold secrets anyway).
- **One value is limited to 128 KB** (the Linux limit for one environment string); larger values are refused with the key name.
- **pm2 cluster mode** preloads once per worker. Wrap `pm2-runtime` instead to load once.
- **The wrapper does not use a shell.** On Windows, wrap an executable (`node.exe ...`), not a `.cmd` script.
- **No HTTP proxy support yet.** Requests go directly to `VAULT_ADDR`.
- Token and AppRole authentication; Kubernetes auth may follow.

## Library API

```js
const { load, loadSync, fetch } = require('vault-env-loader');

await load(options?)     // -> names set in process.env
loadSync(options?)       // same, synchronous (does the HTTP work in a child process)
await fetch(options?)    // -> { NAME: value }; does not touch process.env
```

`options` mirror the variables above (`addr`, `token`, `tokenFile`, `roleId`, `roleIdFile`, `secretId`, `secretIdFile`, `approleMount`, `imports`, `base`, `override`, `keepToken`, `timeout`, `retries`, `namespace`, `cacert`, `env`). Errors are `VaultEnvError` with a `code`: `config`, `auth`, `not_found`, `resolve`, `collision`, `value`, `unavailable`. Messages contain paths and key names, never values or tokens.

## Security notes

- Secret values are never written to logs, error messages, argv or disk.
- `loadSync()` and `-r` run a child Node process to make the HTTP call synchronously. The token (or the AppRole credentials) reaches it through its environment, not its arguments, and the values come back through a pipe. With AppRole the child logs in and revokes; the session token never leaves it.
- The AppRole login body is never logged; `check` shows only the first 8 characters of the role ID.
- Requests carry `User-Agent: vault-env-loader/<version> node/<version>`, so server audit logs can tell which client read what.

## License

MIT

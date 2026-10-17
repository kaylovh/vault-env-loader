# vault-env-loader {{VERSION}} for Python

Load secrets from HashiCorp Vault's KV engine into environment variables **before your application starts**. Code that reads `os.environ` / `os.getenv` keeps working unchanged (Django settings, Flask config, pydantic `BaseSettings`, `django-environ`), and plaintext `.env` files can go.

## What it does

- Reads the Vault paths you list, puts every key into the environment, then starts your application.
- **No code change** for the recommended setup: wrap the start command. On Linux and macOS the wrapper replaces itself with your command (same PID, signals and exit code).
- **Zero dependencies**, one file, standard library only, Python ≥ 3.6.
- **Fails fast**: if a secret cannot be loaded, the application does not start (exit code 78).
- **Spring Cloud Vault style imports**: `vault://secret/my-app/prod/database`.
- **The token stays out of your application**: `VAULT_TOKEN` is removed from the environment it sees.
- **Token or AppRole**: with AppRole it logs in once per start, reads, and revokes the session before the application runs.
- Works with HashiCorp Vault (KV v1 and v2, detected automatically) and Vault-compatible servers.

## Install

```bash
pip install vault-env-loader=={{VERSION}}
```

## Usage

Configure it where you deploy:

```bash
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=hvs.xxxxx                  # or VAULT_TOKEN_FILE=/run/secrets/vault-token
#   or AppRole: VAULT_ROLE_ID=... VAULT_SECRET_ID_FILE=/run/secrets/vault-secret-id
VAULT_ENV_IMPORT="vault://secret/order-service/prod/database, vault://secret/order-service/prod/redis?prefix=REDIS_"
```

Then hook it in, one of:

```bash
vault-env-loader -- gunicorn app.wsgi                    # A. wrap the start command (recommended)
python -m vault_env_loader -- python app.py              #    same, without the script on PATH
```

```python
import vault_env_loader; vault_env_loader.load()         # B. top of manage.py / wsgi.py / the app module
```

`vault-env-loader check` shows what would be loaded: names and lengths, never values.

Full documentation: [python/README.md](https://github.com/kaylovh/vault-env-loader/tree/main/python#readme)

## Changes in {{VERSION}}

{{CHANGES}}

## Verify

Published from GitHub Actions with PyPI Trusted Publishing; the files carry attestations, shown on the [PyPI project page](https://pypi.org/project/vault-env-loader/{{VERSION}}/). The wheel and sdist are attached below.

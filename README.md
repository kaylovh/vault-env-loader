# vault-env-loader

Load secrets from HashiCorp Vault's KV engine into environment variables **before your application starts** — so code that reads `process.env` / `os.environ` keeps working unchanged, and plaintext `.env` files can go.

| Language | Package | Status |
|---|---|---|
| Node.js | [`node/`](./node) — `npm install vault-env-loader` | 0.1.0 |
| Python | [`python/`](./python) — `pip install vault-env-loader` | 0.1.0 |

Both implementations follow one behaviour contract — import syntax, variable naming, precedence, failure handling — checked by the shared cases in [`spec/cases.json`](./spec/cases.json).

```bash
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=hvs.xxxxx
VAULT_ENV_IMPORT="vault://secret/order-service/prod/database"

vault-env-loader -- node server.js
vault-env-loader -- gunicorn app.wsgi
```

## Releasing

1. Bump the version (Node: `node/package.json` and `VERSION` in `node/index.cjs`; Python: `__version__` in `python/vault_env_loader.py`).
2. Add a `## <version>` section to `node/CHANGELOG.md` or `python/CHANGELOG.md`.
3. Push a tag `node-v<version>` or `python-v<version>`.

The release workflow checks the version, runs the tests, publishes with Trusted Publishing (npm provenance / PyPI attestations) and creates the GitHub release. Its notes are `.github/release/<package>.md`, which describes the package and its usage, plus the changelog section.

License: MIT

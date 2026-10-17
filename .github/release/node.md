# vault-env-loader {{VERSION}} for Node.js

Load secrets from HashiCorp Vault's KV engine into environment variables **before your application starts**. Code that reads `process.env` keeps working unchanged, and plaintext `.env` files can go.

## What it does

- Reads the Vault paths you list, puts every key into the environment, then starts your application.
- **No code change** for the recommended setup: wrap the start command.
- **Zero dependencies**, one file, Node ≥ 14.
- **Fails fast**: if a secret cannot be loaded, the application does not start (exit code 78).
- **Spring Cloud Vault style imports**: `vault://secret/my-app/prod/database`.
- **The token stays out of your application**: `VAULT_TOKEN` is removed from the environment it sees.
- **Token or AppRole**: with AppRole it logs in once per start, reads, and revokes the session before the application runs.
- Works with HashiCorp Vault (KV v1 and v2, detected automatically) and Vault-compatible servers.

## Install

```bash
npm install vault-env-loader@{{VERSION}}
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
vault-env-loader -- node server.js                       # A. wrap the start command (recommended)
node -r vault-env-loader/register server.js              # B. preload (CommonJS)
node --import vault-env-loader/register server.mjs       #    preload (ES modules)
```

```js
require('vault-env-loader').loadSync();                  // C. first line of a CommonJS entry file
```

`vault-env-loader check` shows what would be loaded: names and lengths, never values.

Full documentation: [node/README.md](https://github.com/kaylovh/vault-env-loader/tree/main/node#readme)

## Changes in {{VERSION}}

{{CHANGES}}

## Verify

Published from GitHub Actions with npm provenance. Check it with `npm audit signatures` after installing, or on the [npm package page](https://www.npmjs.com/package/vault-env-loader).

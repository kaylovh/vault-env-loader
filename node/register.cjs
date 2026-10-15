'use strict';
// node -r vault-env-loader/register app.js
// Loads Vault secrets into process.env before the application's first line runs.
const lib = require('./index.cjs');

try {
  lib.loadSync();
} catch (e) {
  if (e instanceof lib.VaultEnvError) {
    process.stderr.write(`[vault-env-loader] ${e.message}\n`);
    process.exit(78);
  }
  throw e;
}

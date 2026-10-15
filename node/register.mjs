// node --import vault-env-loader/register app.mjs
// Top-level await: Node finishes this before the entry module starts.
import lib from './index.cjs';

try {
  await lib.load();
} catch (e) {
  if (e instanceof lib.VaultEnvError) {
    process.stderr.write(`[vault-env-loader] ${e.message}\n`);
    process.exit(78);
  }
  throw e;
}

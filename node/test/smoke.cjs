'use strict';
// Smoke test for old Node versions (no node:test before 18):
// the wrapper, `node -r register` and loadSync() against the fake Vault.
//   node test/smoke.cjs
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const INDEX = path.join(__dirname, '..', 'index.cjs');
const TOKEN = 'smoke-token';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vel-smoke-'));
const scenario = path.join(tmp, 'scenario.json');
fs.writeFileSync(
  scenario,
  JSON.stringify({
    token: TOKEN,
    routes: {
      'auth/token/lookup-self': { status: 200, body: { data: { ttl: 0, meta: { application: 'app', environment: 'prod' } } } },
      'sys/internal/ui/mounts/secret/app/prod/db': { status: 200, body: { data: { path: 'secret/', type: 'kv', options: { version: '2' } } } },
      'secret/data/app/prod/db': { status: 200, body: { data: { data: { 'db.password': 's3cr3t' }, metadata: { version: 1 } } } },
    },
  })
);

const server = spawn(process.execPath, [path.join(__dirname, 'fake-vault.cjs'), scenario], { stdio: ['ignore', 'pipe', 'inherit'] });
server.stdout.once('data', (d) => {
  const port = /PORT (\d+)/.exec(String(d))[1];
  const env = Object.assign({}, process.env, { VAULT_ADDR: `http://127.0.0.1:${port}`, VAULT_TOKEN: TOKEN, VAULT_ENV_IMPORT: 'db' });
  const print = 'process.stdout.write(JSON.stringify({ p: process.env.DB_PASSWORD, t: process.env.VAULT_TOKEN || null }))';
  const expect = { p: 's3cr3t', t: null };
  try {
    const runs = {
      wrapper: [INDEX, '--', process.execPath, '-e', print],
      register: ['-r', path.join(__dirname, '..', 'register.cjs'), '-e', print],
      loadSync: ['-e', `require(${JSON.stringify(INDEX)}).loadSync(); ${print}`],
    };
    for (const name of Object.keys(runs)) {
      const out = spawnSync(process.execPath, runs[name], { env });
      assert.strictEqual(out.status, 0, `${name}: ${out.stderr}`);
      assert.deepStrictEqual(JSON.parse(String(out.stdout)), expect, name);
      process.stdout.write(`ok ${name}\n`);
    }
    const bad = spawnSync(process.execPath, runs.wrapper, { env: Object.assign({}, env, { VAULT_TOKEN: 'wrong' }) });
    assert.strictEqual(bad.status, 78, 'failure exits 78');
    process.stdout.write('ok failure exit code\n');
    process.stdout.write(`smoke passed on node ${process.version}\n`);
  } catch (e) {
    process.stderr.write(`${e.stack || e}\n`);
    process.exitCode = 1;
  } finally {
    server.kill();
  }
});

'use strict';
// Smoke test for old Node versions (no node:test before 18):
// the wrapper, `node -r register` and loadSync() against the fake Vault, and
// certificate login (RSA, EC P-256, EC P-384 with an encrypted or separate key),
// which signs with node:crypto alone: no X509Certificate before Node 15.6.
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
const FIXTURES = path.join(__dirname, '..', '..', 'spec', 'fixtures');
const certOf = (f) => /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(fs.readFileSync(path.join(FIXTURES, f), 'utf8'))[0];
const certs = {
  rsa: { env: { VAULT_CLIENT_CERTIFICATE_PATH: path.join(FIXTURES, 'rsa.pem') }, cert: certOf('rsa.pem') },
  p256: { env: { VAULT_CLIENT_CERTIFICATE_PATH: path.join(FIXTURES, 'p256.pem') }, cert: certOf('p256.pem') },
  p384: { env: { VAULT_CLIENT_CERTIFICATE_PATH: path.join(FIXTURES, 'p384-cert.pem'), VAULT_CLIENT_KEY_PATH: path.join(FIXTURES, 'p384-key.pem') }, cert: certOf('p384-cert.pem') },
  encrypted: { env: { VAULT_CLIENT_CERTIFICATE_PATH: path.join(FIXTURES, 'encrypted.pem'), VAULT_CLIENT_CERTIFICATE_PASSWORD: 'fixture-password' }, cert: certOf('encrypted.pem') },
};
function scenarioFor(cert) {
  return JSON.stringify({
    token: TOKEN,
    jwt: cert ? { role: 'smoke-role', certificate: cert } : undefined,
    routes: {
      'auth/token/lookup-self': { status: 200, body: { data: { ttl: 0, meta: { application: 'app', environment: 'prod' } } } },
      'sys/internal/ui/mounts/secret/app/prod/db': { status: 200, body: { data: { path: 'secret/', type: 'kv', options: { version: '2' } } } },
      'secret/data/app/prod/db': { status: 200, body: { data: { data: { 'db.password': 's3cr3t' }, metadata: { version: 1 } } } },
      'auth/token/revoke-self': { status: 204 },
    },
  });
}
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
    certificateLogins(0, () => process.stdout.write(`smoke passed on node ${process.version}\n`));
  } catch (e) {
    process.stderr.write(`${e.stack || e}\n`);
    process.exitCode = 1;
  } finally {
    server.kill();
  }
});

// One fake Vault per key type, each bound to its certificate; wrapper and loadSync().
function certificateLogins(i, done) {
  const names = Object.keys(certs);
  if (i >= names.length) return done();
  const name = names[i];
  const file = path.join(tmp, `scenario-${name}.json`);
  fs.writeFileSync(file, scenarioFor(certs[name].cert));
  const srv = spawn(process.execPath, [path.join(__dirname, 'fake-vault.cjs'), file], { stdio: ['ignore', 'pipe', 'inherit'] });
  srv.stdout.once('data', (d) => {
    const port = /PORT (\d+)/.exec(String(d))[1];
    const env = Object.assign({}, process.env, { VAULT_ADDR: `http://127.0.0.1:${port}`, VAULT_ROLE_ID: 'smoke-role', VAULT_ENV_IMPORT: 'db' }, certs[name].env);
    delete env.VAULT_TOKEN;
    const print = 'process.stdout.write(JSON.stringify({ p: process.env.DB_PASSWORD, t: process.env.VAULT_TOKEN || null, c: process.env.VAULT_CLIENT_CERTIFICATE_PATH || null }))';
    try {
      for (const [how, args] of [['wrapper', [INDEX, '--', process.execPath, '-e', print]], ['loadSync', ['-e', `require(${JSON.stringify(INDEX)}).loadSync(); ${print}`]]]) {
        const out = spawnSync(process.execPath, args, { env });
        assert.strictEqual(out.status, 0, `certificate ${name} ${how}: ${out.stderr}`);
        assert.deepStrictEqual(JSON.parse(String(out.stdout)), { p: 's3cr3t', t: null, c: null }, `certificate ${name} ${how}`);
        process.stdout.write(`ok certificate ${name} ${how}\n`);
      }
      srv.kill();
      certificateLogins(i + 1, done);
    } catch (e) {
      srv.kill();
      process.stderr.write(`${e.stack || e}\n`);
      process.exitCode = 1;
    }
  });
}

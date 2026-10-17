'use strict';
// Against a real HashiCorp Vault dev server. Runs only when VAULT_IT_ADDR and
// VAULT_IT_ROOT_TOKEN are set (CI starts hashicorp/vault as a service):
//   VAULT_IT_ADDR=http://127.0.0.1:8200 VAULT_IT_ROOT_TOKEN=root node --test test/vault.test.cjs
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const path = require('path');
const { spawnSync } = require('child_process');
const lib = require('../index.cjs');

const ADDR = process.env.VAULT_IT_ADDR;
const ROOT = process.env.VAULT_IT_ROOT_TOKEN;
const skip = !ADDR || !ROOT ? 'VAULT_IT_ADDR / VAULT_IT_ROOT_TOKEN not set' : false;

function api(method, p, body, token = ROOT) {
  return new Promise((resolve, reject) => {
    const req = http.request(`${ADDR}/v1/${p}`, { method, headers: { 'X-Vault-Token': token, 'Content-Type': 'application/json' } }, (res) => {
      let s = '';
      res.on('data', (c) => (s += c));
      res.on('end', () => resolve({ status: res.statusCode, body: s ? JSON.parse(s) : null }));
    });
    req.on('error', reject);
    req.end(body ? JSON.stringify(body) : undefined);
  });
}

let reader;
let stranger;
let roleId;
let secretId;
let onceSecretId;

test.before(async () => {
  if (skip) return;
  await api('POST', 'sys/mounts/kv1', { type: 'kv', options: { version: '1' } }); // 400 if it exists: fine
  await api('POST', 'secret/data/app/prod/db', { data: { 'db.password': 's3cr3t', DB_USER: 'app' } });
  await api('POST', 'secret/data/app/prod', { data: { DEFAULT_KEY: 'd' } });
  await api('POST', 'kv1/app/legacy', { LEGACY: '1' });
  const policy = [
    'path "secret/data/app/prod" { capabilities = ["read"] }',
    'path "secret/data/app/prod/*" { capabilities = ["read"] }',
    'path "kv1/app/*" { capabilities = ["read"] }',
    'path "sys/internal/ui/mounts/*" { capabilities = ["read"] }',
  ].join('\n');
  await api('PUT', 'sys/policies/acl/vel-reader', { policy });
  const t = await api('POST', 'auth/token/create', { policies: ['vel-reader'], meta: { application: 'app', environment: 'prod' }, ttl: '1h' });
  reader = t.body.auth.client_token;
  const s = await api('POST', 'auth/token/create', { policies: ['default'], ttl: '1h' });
  stranger = s.body.auth.client_token;
  await api('POST', 'sys/auth/approle', { type: 'approle' }); // 400 if enabled: fine
  await api('POST', 'auth/approle/role/vel', { token_policies: ['vel-reader'], token_ttl: '10m', token_max_ttl: '30m' });
  roleId = (await api('GET', 'auth/approle/role/vel/role-id')).body.data.role_id;
  secretId = (await api('POST', 'auth/approle/role/vel/secret-id', {})).body.data.secret_id;
  onceSecretId = (await api('POST', 'auth/approle/role/vel/secret-id', { num_uses: 1 })).body.data.secret_id;
});

const env = (extra) => Object.assign({ VAULT_ADDR: ADDR, VAULT_TOKEN: reader }, extra);

test('relative imports via token metadata, KV v2', { skip }, async () => {
  const values = await lib.fetch({ env: env({ VAULT_ENV_IMPORT: 'db, vault://' }), retryDelayMs: 1 });
  assert.deepEqual(values, { DB_PASSWORD: 's3cr3t', DB_USER: 'app', DEFAULT_KEY: 'd' });
});

test('KV v1 mount detected automatically', { skip }, async () => {
  const values = await lib.fetch({ env: env({ VAULT_ENV_IMPORT: 'vault://kv1/app/legacy' }), retryDelayMs: 1 });
  assert.deepEqual(values, { LEGACY: '1' });
});

test('a token whose policy does not cover the path', { skip }, async () => {
  await assert.rejects(lib.fetch({ env: env({ VAULT_TOKEN: stranger, VAULT_ENV_IMPORT: 'vault://secret/app/prod/db' }), retryDelayMs: 1 }), (e) => e.code === 'auth');
});

test('missing path: fails, or skipped when optional', { skip }, async () => {
  await assert.rejects(lib.fetch({ env: env({ VAULT_ENV_IMPORT: 'nosuch' }), retryDelayMs: 1 }), (e) => e.code === 'not_found' || e.code === 'auth');
  const values = await lib.fetch({ env: env({ VAULT_ENV_IMPORT: 'db, optional:vault://secret/app/prod/nosuch' }), retryDelayMs: 1 });
  assert.equal(values.DB_USER, 'app');
});

test('CLI wrapper end to end', { skip }, () => {
  const out = spawnSync(process.execPath, [path.join(__dirname, '..', 'index.cjs'), '--', process.execPath, '-e', 'process.stdout.write(process.env.DB_PASSWORD + "|" + (process.env.VAULT_TOKEN || ""))'], {
    env: Object.assign({}, process.env, env({ VAULT_ENV_IMPORT: 'db' })),
  });
  assert.equal(out.status, 0, String(out.stderr));
  assert.equal(String(out.stdout), 's3cr3t|');
});

// AppRole tokens carry only role_name as metadata, so relative imports need VAULT_ENV_BASE.
const roleEnv = (extra) => Object.assign({ VAULT_ADDR: ADDR, VAULT_ROLE_ID: roleId, VAULT_SECRET_ID: secretId, VAULT_ENV_BASE: 'secret/app/prod' }, extra);

test('AppRole login against real Vault', { skip }, async () => {
  const values = await lib.fetch({ env: roleEnv({ VAULT_ENV_IMPORT: 'db' }), retryDelayMs: 1 });
  assert.deepEqual(values, { DB_PASSWORD: 's3cr3t', DB_USER: 'app' });
});

test('AppRole: a single-use secret ID logs in once', { skip }, async () => {
  const env = () => roleEnv({ VAULT_SECRET_ID: onceSecretId, VAULT_ENV_IMPORT: 'db' });
  assert.equal((await lib.fetch({ env: env(), retryDelayMs: 1 })).DB_USER, 'app');
  await assert.rejects(lib.fetch({ env: env(), retryDelayMs: 1 }), (e) => e.code === 'auth');
});

test('AppRole: a wrong secret ID is refused', { skip }, async () => {
  await assert.rejects(lib.fetch({ env: roleEnv({ VAULT_SECRET_ID: 'nope', VAULT_ENV_IMPORT: 'db' }), retryDelayMs: 1 }), (e) => e.code === 'auth');
});

test('AppRole: CLI wrapper end to end, credentials stripped', { skip }, () => {
  const print = 'process.stdout.write([process.env.DB_PASSWORD, process.env.VAULT_ROLE_ID || "", process.env.VAULT_SECRET_ID || "", process.env.VAULT_TOKEN || ""].join("|"))';
  const base = Object.assign({}, process.env);
  delete base.VAULT_TOKEN;
  const out = spawnSync(process.execPath, [path.join(__dirname, '..', 'index.cjs'), '--', process.execPath, '-e', print], {
    env: Object.assign(base, roleEnv({ VAULT_ENV_IMPORT: 'db' })),
  });
  assert.equal(out.status, 0, String(out.stderr));
  assert.equal(String(out.stdout), 's3cr3t|||');
});

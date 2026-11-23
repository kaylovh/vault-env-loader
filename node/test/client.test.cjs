'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const lib = require('../index.cjs');

const INDEX = path.join(__dirname, '..', 'index.cjs');
const REGISTER_CJS = path.join(__dirname, '..', 'register.cjs');
const REGISTER_MJS = path.join(__dirname, '..', 'register.mjs');
const TOKEN = 'test-token-123';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vel-'));

// ---------------------------------------------------------------------------
// helpers

const v2 = (data, version = 1) => ({ status: 200, body: { data: { data, metadata: { version } } } });
const self = (meta, ttl = 0) => ({ status: 200, body: { data: { ttl, meta } } });
const mounts = (version) => ({ status: 200, body: { data: { path: 'secret/', type: 'kv', options: { version: String(version) } } } });
const BOUND = { application: 'order-service', environment: 'prod' };

let n = 0;
async function fake(routes, extra = {}) {
  const file = path.join(tmp, `scenario-${n++}.json`);
  fs.writeFileSync(file, JSON.stringify(Object.assign({ token: TOKEN, routes }, extra)));
  const proc = spawn(process.execPath, [path.join(__dirname, 'fake-vault.cjs'), file], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise((resolve, reject) => {
    proc.stdout.once('data', (d) => resolve(Number(/PORT (\d+)/.exec(String(d))[1])));
    proc.once('error', reject);
  });
  const addr = `http://127.0.0.1:${port}`;
  return {
    addr,
    async requests() {
      return new Promise((resolve) => {
        require('http').get(`${addr}/_requests`, (res) => {
          let s = '';
          res.on('data', (c) => (s += c));
          res.on('end', () => resolve(JSON.parse(s)));
        });
      });
    },
    stop: () => proc.kill(),
  };
}

function baseEnv(addr, extra) {
  return Object.assign({ VAULT_ADDR: addr, VAULT_TOKEN: TOKEN }, extra);
}

async function captureStderr(fn) {
  const orig = process.stderr.write.bind(process.stderr);
  let out = '';
  process.stderr.write = (chunk, ...rest) => {
    out += chunk;
    return true;
  };
  try {
    const value = await fn();
    return { value, stderr: out };
  } finally {
    process.stderr.write = orig;
  }
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (e) => {
    assert.ok(e instanceof lib.VaultEnvError, String(e));
    assert.equal(e.code, code, e.message);
    return true;
  });
}

const FAST = { retryDelayMs: 1 };

// ---------------------------------------------------------------------------
// configuration

test('not configured: load() is a no-op', async () => {
  const env = {};
  const { value, stderr } = await captureStderr(() => lib.load({ env }));
  assert.deepEqual(value, []);
  assert.match(stderr, /not set; nothing loaded/);
});

test('partial configuration fails', async () => {
  await rejectsCode(lib.load({ env: { VAULT_ENV_IMPORT: 'db' } }), 'config');
  await rejectsCode(lib.load({ env: { VAULT_ADDR: 'https://v.example.com', VAULT_ENV_IMPORT: 'db' } }), 'config');
});

test('VAULT_SKIP_VERIFY is refused, not ignored', async () => {
  await rejectsCode(lib.load({ env: { VAULT_ADDR: 'https://v.example.com', VAULT_TOKEN: 't', VAULT_ENV_IMPORT: 'db', VAULT_SKIP_VERIFY: 'true' } }), 'config');
  // An explicit false is fine.
  assert.equal(lib._internal.readConfig({}, { VAULT_ADDR: 'https://v.example.com', VAULT_TOKEN: 't', VAULT_ENV_IMPORT: 'db', VAULT_SKIP_VERIFY: 'false' }).configured, true);
});

test('plain http only to loopback unless allowed', () => {
  const env = { VAULT_TOKEN: 't', VAULT_ENV_IMPORT: 'db' };
  assert.throws(() => lib._internal.readConfig({}, Object.assign({ VAULT_ADDR: 'http://vault.internal:8200' }, env)), /plain http/);
  assert.equal(lib._internal.readConfig({}, Object.assign({ VAULT_ADDR: 'http://vault.internal:8200', VAULT_ENV_ALLOW_HTTP: 'true' }, env)).insecureHttp, true);
  assert.equal(lib._internal.readConfig({}, Object.assign({ VAULT_ADDR: 'http://localhost:8200' }, env)).insecureHttp, false);
});

test('token from file', () => {
  const f = path.join(tmp, 'token');
  fs.writeFileSync(f, `  ${TOKEN}\n`);
  const cfg = lib._internal.readConfig({}, { VAULT_ADDR: 'https://v.example.com', VAULT_TOKEN_FILE: f, VAULT_ENV_IMPORT: 'db' });
  assert.equal(cfg.token, TOKEN);
  assert.equal(cfg.tokenFromFile, true);
});

test('--token is refused on the command line', () => {
  assert.throws(() => lib._internal.parseArgs(['--token', 'x', '--', 'true']), /no --token option/);
});

// ---------------------------------------------------------------------------
// reading

test('relative imports resolve against token metadata; names mapped; headers sent', async () => {
  const v = await fake({
    'auth/token/lookup-self': self(BOUND),
    'sys/internal/ui/mounts/secret/order-service/prod/database': mounts(2),
    'secret/data/order-service/prod/database': v2({ 'db.password': 's3cr3t', DB_USER: 'app' }, 7),
    'sys/internal/ui/mounts/secret/order-service/prod': mounts(2),
    'secret/data/order-service/prod': v2({ DEFAULT_ONE: 'd' }),
  });
  try {
    const env = baseEnv(v.addr, { VAULT_ENV_IMPORT: 'database, vault://' });
    const names = await lib.load(Object.assign({ env }, FAST));
    assert.deepEqual(names.sort(), ['DB_PASSWORD', 'DB_USER', 'DEFAULT_ONE']);
    assert.equal(env.DB_PASSWORD, 's3cr3t');
    assert.equal(env.VAULT_ENV_LOADED, '1');
    assert.equal(env.VAULT_TOKEN, undefined, 'token removed after loading');
    const reqs = await v.requests();
    assert.ok(reqs.every((r) => r.token === TOKEN));
    assert.match(reqs[0].ua, /^vault-env-loader\/\d+\.\d+\.\d+ node\//);
  } finally {
    v.stop();
  }
});

test('KV v1 detected through ui/mounts', async () => {
  const v = await fake({
    'auth/token/lookup-self': self(BOUND),
    'sys/internal/ui/mounts/secret/order-service/prod/legacy': mounts(1),
    'secret/order-service/prod/legacy': { status: 200, body: { data: { A: '1' } } },
  });
  try {
    const values = await lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'legacy' }) }, FAST));
    assert.deepEqual(values, { A: '1' });
  } finally {
    v.stop();
  }
});

test('explicit kv=1 skips the probe', async () => {
  const v = await fake({ 'auth/token/lookup-self': self(BOUND), 'secret/order-service/prod/legacy': { status: 200, body: { data: { A: '1' } } } });
  try {
    await lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'legacy?kv=1' }) }, FAST));
    assert.ok(!(await v.requests()).some((r) => r.path.startsWith('sys/internal')));
  } finally {
    v.stop();
  }
});

test('absolute path for another app/env fails locally, before any read', async () => {
  const v = await fake({ 'auth/token/lookup-self': self(BOUND) });
  try {
    await rejectsCode(lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://secret/order-service/dev/database' }) }, FAST)), 'config');
    assert.deepEqual((await v.requests()).map((r) => r.path), ['auth/token/lookup-self']);
  } finally {
    v.stop();
  }
});

test('lookup-self denied (plain Vault policy): absolute works, relative explains', async () => {
  const v = await fake({
    'auth/token/lookup-self': { status: 403, body: { errors: ['permission denied'] } },
    'sys/internal/ui/mounts/kv/team/app': { status: 200, body: { data: { path: 'kv/', type: 'kv', options: { version: '2' } } } },
    'kv/data/team/app': v2({ X: 'y' }),
  });
  try {
    assert.deepEqual(await lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://kv/team/app' }) }, FAST)), { X: 'y' });
    await rejectsCode(lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'app' }) }, FAST)), 'auth');
  } finally {
    v.stop();
  }
});

test('VAULT_ENV_BASE wins over token metadata', async () => {
  const v = await fake({ 'auth/token/lookup-self': self(BOUND), 'kv/data/x/y/z': v2({ Q: '1' }) });
  try {
    const values = await lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'z?kv=2', VAULT_ENV_BASE: 'kv/x/y' }) }, FAST));
    assert.deepEqual(values, { Q: '1' });
  } finally {
    v.stop();
  }
});

test('a wrong token is not retried', async () => {
  const v = await fake({ 'secret/data/a/b': v2({ A: '1' }) });
  try {
    const env = baseEnv(v.addr, { VAULT_TOKEN: 'wrong', VAULT_ENV_IMPORT: 'vault://secret/a/b?kv=2' });
    await rejectsCode(lib.fetch(Object.assign({ env }, FAST)), 'auth');
    const reads = (await v.requests()).filter((r) => r.path === 'secret/data/a/b');
    assert.equal(reads.length, 1);
  } finally {
    v.stop();
  }
});

test('503 then 200 is retried', async () => {
  const v = await fake({ 'secret/data/a/b': [{ status: 503, body: { errors: ['sealed'] } }, v2({ A: '1' })] });
  try {
    assert.deepEqual(await lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://secret/a/b?kv=2' }) }, FAST)), { A: '1' });
  } finally {
    v.stop();
  }
});

test('retries are bounded', async () => {
  const v = await fake({ 'secret/data/a/b': { status: 503, body: { errors: [] } } });
  try {
    await rejectsCode(lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://secret/a/b?kv=2', VAULT_ENV_RETRIES: '2' }) }, FAST)), 'unavailable');
    assert.equal((await v.requests()).filter((r) => r.path === 'secret/data/a/b').length, 3);
  } finally {
    v.stop();
  }
});

test('per-key 502 reasons: transient reasons retried, permanent ones not', async () => {
  const unresolved = (reason) => ({ status: 502, body: { errors: [`alias 'password' could not be resolved: ${reason}`] } });
  const v = await fake({
    'secret/data/a/t': [unresolved('timeout'), v2({ A: '1' })],
    'secret/data/a/p': unresolved('grant_revoked'),
  });
  try {
    assert.deepEqual(await lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://secret/a/t?kv=2' }) }, FAST)), { A: '1' });
    await assert.rejects(
      lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://secret/a/p?kv=2' }) }, FAST)),
      (e) => e.code === 'resolve' && /password \(grant_revoked\)/.test(e.message)
    );
    assert.equal((await v.requests()).filter((r) => r.path === 'secret/data/a/p').length, 1);
  } finally {
    v.stop();
  }
});

test('timeouts are reported and retried', async () => {
  const v = await fake({ 'secret/data/a/b': [{ hang: true }, v2({ A: '1' })] });
  try {
    const env = baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://secret/a/b?kv=2', VAULT_ENV_TIMEOUT: '0.3' });
    assert.deepEqual(await lib.fetch(Object.assign({ env }, FAST)), { A: '1' });
  } finally {
    v.stop();
  }
});

test('optional: only a missing path is skipped', async () => {
  const v = await fake({ 'secret/data/a/b': v2({ A: '1' }), 'secret/data/a/denied': { status: 403, body: { errors: ['permission denied'] } } });
  try {
    const ok = await lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://secret/a/b?kv=2, optional:vault://secret/a/missing?kv=2' }) }, FAST));
    assert.deepEqual(ok, { A: '1' });
    await rejectsCode(lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://secret/a/missing?kv=2' }) }, FAST)), 'not_found');
    await rejectsCode(lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'optional:vault://secret/a/denied?kv=2' }) }, FAST)), 'auth');
  } finally {
    v.stop();
  }
});

test('existing variables win unless override; warnings name variables, never values', async () => {
  const v = await fake({ 'secret/data/a/b': v2({ A: 'from-vault', B: 'from-vault' }) });
  try {
    const env = baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://secret/a/b?kv=2', A: 'local' });
    const { stderr } = await captureStderr(() => lib.load(Object.assign({ env }, FAST)));
    assert.equal(env.A, 'local');
    assert.equal(env.B, 'from-vault');
    assert.match(stderr, /kept as is.*: A\./);
    assert.ok(!stderr.includes('from-vault'));

    const env2 = baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://secret/a/b?kv=2', VAULT_ENV_OVERRIDE: 'true', A: 'local' });
    await lib.load(Object.assign({ env: env2 }, FAST));
    assert.equal(env2.A, 'from-vault');
  } finally {
    v.stop();
  }
});

test('a short-lived token produces a warning; a non-expiring one does not', async () => {
  const soon = await fake({ 'auth/token/lookup-self': self(BOUND, 3 * 86400), 'secret/data/a/b': v2({ A: '1' }) });
  const never = await fake({ 'auth/token/lookup-self': self(BOUND, 0), 'secret/data/a/b': v2({ A: '1' }) });
  try {
    const imp = { VAULT_ENV_IMPORT: 'vault://secret/a/b?kv=2' };
    const a = await captureStderr(() => lib.fetch(Object.assign({ env: baseEnv(soon.addr, imp), base: 'secret/a' }, FAST)));
    assert.match(a.stderr, /expires in 3 day/);
    const b = await captureStderr(() => lib.fetch(Object.assign({ env: baseEnv(never.addr, imp), base: 'secret/a' }, FAST)));
    assert.doesNotMatch(b.stderr, /expires/);
  } finally {
    soon.stop();
    never.stop();
  }
});

test('values over 128 KB are refused with the key name', async () => {
  const v = await fake({ 'secret/data/a/b': v2({ BIG: 'x'.repeat(130 * 1024) }) });
  try {
    await assert.rejects(lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://secret/a/b?kv=2' }) }, FAST)), (e) => e.code === 'value' && /"BIG"/.test(e.message));
  } finally {
    v.stop();
  }
});

test('namespace header', async () => {
  const v = await fake({ 'secret/data/a/b': v2({ A: '1' }) });
  try {
    await lib.fetch(Object.assign({ env: baseEnv(v.addr, { VAULT_ENV_IMPORT: 'vault://secret/a/b?kv=2', VAULT_NAMESPACE: 'team-a' }) }, FAST));
    assert.ok((await v.requests()).every((r) => r.ns === 'team-a'));
  } finally {
    v.stop();
  }
});

// ---------------------------------------------------------------------------
// processes: loadSync, register, CLI

const PRINT_ENV = `process.stdout.write(JSON.stringify({ DB_PASSWORD: process.env.DB_PASSWORD, VAULT_TOKEN: process.env.VAULT_TOKEN || null, LOADED: process.env.VAULT_ENV_LOADED || null }))`;

function childEnv(addr, extra) {
  const env = Object.assign({}, process.env, { VAULT_ADDR: addr, VAULT_TOKEN: TOKEN, VAULT_ENV_IMPORT: 'database' }, extra);
  delete env.NODE_TEST_CONTEXT;
  delete env.DB_PASSWORD;
  if (!extra || !('VAULT_ENV_ENABLED' in extra)) delete env.VAULT_ENV_ENABLED;
  return env;
}

const ROUTES = {
  'auth/token/lookup-self': self(BOUND),
  'sys/internal/ui/mounts/secret/order-service/prod/database': mounts(2),
  'secret/data/order-service/prod/database': v2({ 'db.password': 's3cr3t' }),
};

test('loadSync() works from a CommonJS entry and removes the token', async () => {
  const v = await fake(ROUTES);
  try {
    const out = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(INDEX)}).loadSync(); ${PRINT_ENV}`], { env: childEnv(v.addr) });
    assert.equal(out.status, 0, String(out.stderr));
    assert.deepEqual(JSON.parse(out.stdout), { DB_PASSWORD: 's3cr3t', VAULT_TOKEN: null, LOADED: '1' });
  } finally {
    v.stop();
  }
});

test('node -r register', async () => {
  const v = await fake(ROUTES);
  try {
    const out = spawnSync(process.execPath, ['-r', REGISTER_CJS, '-e', PRINT_ENV], { env: childEnv(v.addr) });
    assert.equal(out.status, 0, String(out.stderr));
    assert.equal(JSON.parse(out.stdout).DB_PASSWORD, 's3cr3t');
  } finally {
    v.stop();
  }
});

test('NODE_OPTIONS=-r register does not recurse, and child node processes do not reload', async () => {
  const v = await fake(ROUTES);
  try {
    const nested = `const r = require('child_process').spawnSync(process.execPath, ['-e', ${JSON.stringify(PRINT_ENV)}]); process.stdout.write(r.stdout)`;
    const out = spawnSync(process.execPath, ['-e', nested], { env: childEnv(v.addr, { NODE_OPTIONS: `-r ${REGISTER_CJS}` }), timeout: 20000 });
    assert.equal(out.status, 0, String(out.stderr));
    assert.equal(JSON.parse(out.stdout).DB_PASSWORD, 's3cr3t');
    const reads = (await v.requests()).filter((r) => r.path === 'secret/data/order-service/prod/database');
    assert.equal(reads.length, 1, 'read exactly once');
  } finally {
    v.stop();
  }
});

test('node --import register (ESM, top-level await)', async () => {
  const v = await fake(ROUTES);
  try {
    const entry = path.join(tmp, 'entry.mjs');
    fs.writeFileSync(entry, PRINT_ENV);
    const out = spawnSync(process.execPath, ['--import', require('url').pathToFileURL(REGISTER_MJS).href, entry], { env: childEnv(v.addr) });
    assert.equal(out.status, 0, String(out.stderr));
    assert.equal(JSON.parse(out.stdout).DB_PASSWORD, 's3cr3t');
  } finally {
    v.stop();
  }
});

test('register exits 78 with one clear line on failure', async () => {
  const v = await fake(ROUTES);
  try {
    const out = spawnSync(process.execPath, ['-r', REGISTER_CJS, '-e', 'console.log("app ran")'], { env: childEnv(v.addr, { VAULT_TOKEN: 'wrong' }) });
    assert.equal(out.status, 78);
    assert.equal(String(out.stdout), '');
    assert.match(String(out.stderr), /\[vault-env-loader\] .*(Permission denied|permission denied)/);
    assert.ok(!String(out.stderr).includes('wrong'), 'token not echoed');
  } finally {
    v.stop();
  }
});

test('CLI wrapper: injects, strips the token, passes the exit code through', async () => {
  const v = await fake(ROUTES);
  try {
    const out = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', `${PRINT_ENV}; process.exit(3)`], { env: childEnv(v.addr) });
    assert.equal(out.status, 3, String(out.stderr));
    assert.deepEqual(JSON.parse(out.stdout), { DB_PASSWORD: 's3cr3t', VAULT_TOKEN: null, LOADED: '1' });
  } finally {
    v.stop();
  }
});

test('CLI wrapper: on failure the command never runs; exit 78', async () => {
  const v = await fake(ROUTES);
  try {
    const out = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', 'console.log("app ran")'], { env: childEnv(v.addr, { VAULT_ENV_IMPORT: 'missing' }) });
    assert.equal(out.status, 78);
    assert.equal(String(out.stdout), '');
    assert.match(String(out.stderr), /Not found/);
  } finally {
    v.stop();
  }
});

test('CLI wrapper: not configured runs the command anyway', () => {
  const env = Object.assign({}, process.env);
  for (const k of Object.keys(env)) if (k.startsWith('VAULT_')) delete env[k];
  const out = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', 'process.stdout.write("ran")'], { env });
  assert.equal(out.status, 0);
  assert.equal(String(out.stdout), 'ran');
});

test('CLI wrapper: command not found is 127', async () => {
  const v = await fake(ROUTES);
  try {
    const out = spawnSync(process.execPath, [INDEX, '--', 'definitely-not-a-command-xyz'], { env: childEnv(v.addr) });
    assert.equal(out.status, 127);
  } finally {
    v.stop();
  }
});

test('check prints names and lengths, never values', async () => {
  const v = await fake(ROUTES);
  try {
    const out = spawnSync(process.execPath, [INDEX, 'check'], { env: childEnv(v.addr) });
    assert.equal(out.status, 0, String(out.stderr));
    const s = String(out.stdout);
    assert.match(s, /DB_PASSWORD\s+6 chars\s+\(from db\.password\)/);
    assert.match(s, /secret\/order-service\/prod\/database\s+\(kv v2, version 1\)/);
    assert.ok(!s.includes('s3cr3t'));
  } finally {
    v.stop();
  }
});

test('SIGTERM is forwarded to the wrapped command', { skip: process.platform === 'win32' }, async () => {
  const v = await fake(ROUTES);
  try {
    const script = `process.on('SIGTERM', () => { process.stdout.write('got-term'); process.exit(0); }); process.stdout.write('ready'); setInterval(() => {}, 1000);`;
    const child = spawn(process.execPath, [INDEX, '--', process.execPath, '-e', script], { env: childEnv(v.addr) });
    let out = '';
    await new Promise((resolve) => child.stdout.on('data', (d) => ((out += d), out.includes('ready') && resolve())));
    child.kill('SIGTERM');
    const code = await new Promise((resolve) => child.on('exit', (c) => resolve(c)));
    assert.equal(code, 0);
    assert.match(out, /got-term/);
  } finally {
    v.stop();
  }
});

// ---------------------------------------------------------------------------
// AppRole (0.2)

const ROLE = { role_id: 'role-123', secret_id: 'secret-456' };
const APPROLE_ROUTES = Object.assign({ 'auth/token/revoke-self': { status: 204 } }, ROUTES);

function roleEnv(addr, extra) {
  const env = childEnv(addr, Object.assign({ VAULT_ROLE_ID: ROLE.role_id, VAULT_SECRET_ID: ROLE.secret_id }, extra));
  delete env.VAULT_TOKEN;
  return env;
}

test('AppRole: log in, read with the session, revoke it', async () => {
  const v = await fake(APPROLE_ROUTES, { approle: ROLE });
  try {
    const env = roleEnv(v.addr);
    const { value, stderr } = await captureStderr(() => lib.load(Object.assign({ env }, FAST)));
    assert.deepEqual(value, ['DB_PASSWORD']);
    assert.equal(env.DB_PASSWORD, 's3cr3t');
    assert.equal(env.VAULT_ROLE_ID, undefined);
    assert.equal(env.VAULT_SECRET_ID, undefined);
    assert.ok(!/expires in/.test(stderr), 'a short session TTL is not worth a warning');
    const reqs = await v.requests();
    assert.deepEqual(reqs.map((r) => `${r.method} ${r.path}`), [
      'POST auth/approle/login',
      'GET auth/token/lookup-self',
      'GET sys/internal/ui/mounts/secret/order-service/prod/database',
      'GET secret/data/order-service/prod/database',
      'POST auth/token/revoke-self',
    ]);
    assert.equal(reqs[0].token, null);
    assert.deepEqual(reqs[0].body, { role_id: 'role-123', secret_id: '***' });
    assert.ok(reqs.slice(1).every((r) => r.token === TOKEN));
  } finally {
    v.stop();
  }
});

test('AppRole: a wrong secret ID fails once, with no read', async () => {
  const v = await fake(APPROLE_ROUTES, { approle: ROLE });
  try {
    await rejectsCode(lib.load(Object.assign({ env: roleEnv(v.addr, { VAULT_SECRET_ID: 'wrong' }) }, FAST)), 'auth');
    assert.deepEqual((await v.requests()).map((r) => r.path), ['auth/approle/login']);
  } finally {
    v.stop();
  }
});

test('AppRole: the session is revoked even when a read fails', async () => {
  const v = await fake(APPROLE_ROUTES, { approle: ROLE });
  try {
    await rejectsCode(lib.load(Object.assign({ env: roleEnv(v.addr, { VAULT_ENV_IMPORT: 'missing' }) }, FAST)), 'not_found');
    assert.equal((await v.requests()).pop().path, 'auth/token/revoke-self');
  } finally {
    v.stop();
  }
});

test('AppRole: a failed revoke only warns', async () => {
  const v = await fake(Object.assign({}, APPROLE_ROUTES, { 'auth/token/revoke-self': { status: 500, body: { errors: [] } } }), { approle: ROLE });
  try {
    const env = roleEnv(v.addr);
    const { stderr } = await captureStderr(() => lib.load(Object.assign({ env }, FAST)));
    assert.equal(env.DB_PASSWORD, 's3cr3t');
    assert.match(stderr, /Could not revoke the AppRole session \(HTTP 500\); it expires by itself/);
  } finally {
    v.stop();
  }
});

test('AppRole: a token wins; AppRole variables are left for whoever set them', async () => {
  const v = await fake(ROUTES);
  try {
    const env = childEnv(v.addr, { VAULT_ROLE_ID: 'r', VAULT_SECRET_ID: 's' });
    const { stderr } = await captureStderr(() => lib.load(Object.assign({ env }, FAST)));
    assert.equal(env.DB_PASSWORD, 's3cr3t');
    assert.equal(env.VAULT_ROLE_ID, 'r');
    assert.equal(env.VAULT_SECRET_ID, 's');
    assert.match(stderr, /VAULT_TOKEN is set, so VAULT_ROLE_ID \/ VAULT_SECRET_ID are ignored/);
    assert.ok(!(await v.requests()).some((r) => r.path.endsWith('/login')));
  } finally {
    v.stop();
  }
});

test('AppRole: login retried on 503, not after a 500 or once the request went out', async () => {
  const v = await fake(Object.assign({}, APPROLE_ROUTES, { 'auth/approle/login': [{ status: 503, body: { errors: [] } }, { status: 200, body: { auth: { client_token: TOKEN } } }] }));
  try {
    const env = roleEnv(v.addr);
    await lib.load(Object.assign({ env }, FAST));
    assert.equal(env.DB_PASSWORD, 's3cr3t');
  } finally {
    v.stop();
  }
  const v500 = await fake(Object.assign({}, APPROLE_ROUTES, { 'auth/approle/login': { status: 500, body: { errors: [] } } }));
  try {
    await rejectsCode(lib.load(Object.assign({ env: roleEnv(v500.addr) }, FAST)), 'unavailable');
    assert.equal((await v500.requests()).length, 1);
  } finally {
    v500.stop();
  }
  const hang = await fake(Object.assign({}, APPROLE_ROUTES, { 'auth/approle/login': { hang: true } }));
  try {
    await rejectsCode(lib.load(Object.assign({ env: roleEnv(hang.addr, { VAULT_ENV_TIMEOUT: '0.3' }) }, FAST)), 'unavailable');
    assert.equal((await hang.requests()).length, 1, 'a login the server may have processed is not repeated');
  } finally {
    hang.stop();
  }
});

test('AppRole: a refused connection is retried (the server never saw it)', async () => {
  const net = require('net');
  const port = await new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const p = srv.address().port;
      srv.close(() => resolve(p));
    });
  });
  const started = Date.now();
  await rejectsCode(lib.load({ env: roleEnv(`http://127.0.0.1:${port}`, { VAULT_ENV_RETRIES: '2' }), retryDelayMs: 50 }), 'unavailable');
  assert.ok(Date.now() - started >= 140, 'two retries with 50 ms and 100 ms backoff');
});

test('AppRole: CLI wrapper strips the AppRole variables it used and keeps the rest', async () => {
  const v = await fake(APPROLE_ROUTES, { approle: ROLE });
  try {
    const file = path.join(tmp, 'unused-role-id');
    fs.writeFileSync(file, 'other');
    const print = 'process.stdout.write(JSON.stringify({ DB_PASSWORD: process.env.DB_PASSWORD, R: process.env.VAULT_ROLE_ID || null, S: process.env.VAULT_SECRET_ID || null, RF: process.env.VAULT_ROLE_ID_FILE || null, T: process.env.VAULT_TOKEN || null }))';
    const out = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', print], { env: roleEnv(v.addr, { VAULT_ROLE_ID_FILE: file }) });
    assert.equal(out.status, 0, String(out.stderr));
    assert.deepEqual(JSON.parse(out.stdout), { DB_PASSWORD: 's3cr3t', R: null, S: null, RF: file, T: null });
  } finally {
    v.stop();
  }
});

test('AppRole: --secret-id is refused on the command line', () => {
  const out = spawnSync(process.execPath, [INDEX, '--secret-id', 'x', '--', 'true'], { env: {} });
  assert.equal(out.status, 78);
  assert.match(String(out.stderr), /no --secret-id option/);
});

test('AppRole: loadSync() logs in inside the worker; the session never reaches the parent', async () => {
  const v = await fake(APPROLE_ROUTES, { approle: ROLE });
  try {
    const print = 'process.stdout.write(JSON.stringify({ DB_PASSWORD: process.env.DB_PASSWORD, T: process.env.VAULT_TOKEN || null, S: process.env.VAULT_SECRET_ID || null }))';
    const out = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(INDEX)}).loadSync(); ${print}`], { env: roleEnv(v.addr) });
    assert.equal(out.status, 0, String(out.stderr));
    assert.deepEqual(JSON.parse(out.stdout), { DB_PASSWORD: 's3cr3t', T: null, S: null });
    assert.equal((await v.requests()).pop().path, 'auth/token/revoke-self');
  } finally {
    v.stop();
  }
});

test('AppRole: check names the auth method and revokes its session', async () => {
  const v = await fake(APPROLE_ROUTES, { approle: ROLE });
  try {
    const out = spawnSync(process.execPath, [INDEX, 'check'], { env: roleEnv(v.addr) });
    assert.equal(out.status, 0, String(out.stderr));
    assert.match(String(out.stdout), /auth\s+approle \(role_id role-123\.\.\., mount approle; session revoked after reading\)/);
    assert.ok(!String(out.stdout).includes('secret-456'));
    assert.equal((await v.requests()).pop().path, 'auth/token/revoke-self');
  } finally {
    v.stop();
  }
});

test('AppRole: another mount', async () => {
  const v = await fake(APPROLE_ROUTES, { approle: Object.assign({ mount: 'ci/approle' }, ROLE) });
  try {
    const env = roleEnv(v.addr, { VAULT_ENV_APPROLE_MOUNT: 'ci/approle' });
    await lib.load(Object.assign({ env }, FAST));
    assert.equal(env.DB_PASSWORD, 's3cr3t');
    assert.equal((await v.requests())[0].path, 'auth/ci/approle/login');
  } finally {
    v.stop();
  }
});

// ---------------------------------------------------------------------------
// Certificate login (0.4)

const FIXTURES = path.join(__dirname, '..', '..', 'spec', 'fixtures');
const RSA_PEM = path.join(FIXTURES, 'rsa.pem');
const P256_PEM = path.join(FIXTURES, 'p256.pem');
const RSA_X5T = 'TRPxIPG0IpPpJQ7BRpygD3zOwAQ5JyYr2uVlTklRjyk';
const certOf = (file) => /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(fs.readFileSync(file, 'utf8'))[0];
const JWT_ROLE = { role: 'role-123', certificate: certOf(RSA_PEM) };
const CERT_LOGIN_FAILED = 'Certificate login failed: the role ID or certificate is not accepted (mount jwt).';

function certEnv(addr, extra) {
  const env = childEnv(addr, Object.assign({ VAULT_ROLE_ID: 'role-123', VAULT_CLIENT_CERTIFICATE_PATH: RSA_PEM }, extra));
  delete env.VAULT_TOKEN;
  return env;
}

const logins = (reqs) => reqs.filter((r) => r.path === 'auth/jwt/login');

test('certificate: sign, log in, read with the session, revoke it', async () => {
  const v = await fake(APPROLE_ROUTES, { jwt: JWT_ROLE });
  try {
    const env = certEnv(v.addr);
    const started = Math.floor(Date.now() / 1000);
    const { value, stderr } = await captureStderr(() => lib.load(Object.assign({ env }, FAST)));
    assert.deepEqual(value, ['DB_PASSWORD']);
    assert.equal(env.DB_PASSWORD, 's3cr3t');
    assert.equal(env.VAULT_ROLE_ID, undefined);
    assert.equal(env.VAULT_CLIENT_CERTIFICATE_PATH, undefined);
    assert.equal(env.VAULT_TOKEN, undefined);
    assert.ok(fs.existsSync(RSA_PEM), 'the file itself is never touched');
    assert.equal(stderr, '', 'no warning for a certificate that is valid for years');
    const reqs = await v.requests();
    assert.deepEqual(reqs.map((r) => `${r.method} ${r.path}`), [
      'POST auth/jwt/login',
      'GET auth/token/lookup-self',
      'GET sys/internal/ui/mounts/secret/order-service/prod/database',
      'GET secret/data/order-service/prod/database',
      'POST auth/token/revoke-self',
    ]);
    assert.equal(reqs[0].token, null);
    assert.deepEqual(Object.keys(reqs[0].body), ['role', 'jwt', 'assertion']);
    const { header, claims } = reqs[0].body.assertion;
    assert.deepEqual(header, { alg: 'RS256', typ: 'JWT', 'x5t#S256': RSA_X5T });
    assert.equal(claims.aud, `${v.addr}/v1/auth/jwt/login`);
    assert.ok(claims.iat >= started && claims.exp === claims.iat + 120);
    assert.ok(reqs.slice(1).every((r) => r.token === TOKEN));
  } finally {
    v.stop();
  }
});

test('certificate: EC P-256, a separate key file and another mount', async () => {
  const v = await fake(APPROLE_ROUTES, { jwt: { role: 'role-123', certificate: certOf(P256_PEM), mount: 'ci/jwt' } });
  try {
    const env = certEnv(v.addr, { VAULT_CLIENT_CERTIFICATE_PATH: path.join(FIXTURES, 'p256.pem'), VAULT_CLIENT_KEY_PATH: P256_PEM, VAULT_ENV_JWT_MOUNT: 'ci/jwt' });
    await lib.load(Object.assign({ env }, FAST));
    assert.equal(env.DB_PASSWORD, 's3cr3t');
    assert.equal(env.VAULT_CLIENT_KEY_PATH, undefined);
    const login = (await v.requests())[0];
    assert.equal(login.path, 'auth/ci/jwt/login');
    assert.equal(login.body.assertion.header.alg, 'ES256');
  } finally {
    v.stop();
  }
});

test('certificate: a refused login fails once with exit 78, without the server text', async () => {
  const v = await fake(APPROLE_ROUTES, { jwt: Object.assign({}, JWT_ROLE, { role: 'another-role' }) });
  try {
    const out = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', 'process.exit(0)'], { env: certEnv(v.addr) });
    assert.equal(out.status, 78);
    assert.equal(String(out.stderr), `[vault-env-loader] ${CERT_LOGIN_FAILED}\n`);
    assert.deepEqual((await v.requests()).map((r) => r.path), ['auth/jwt/login']);
  } finally {
    v.stop();
  }
});

test('certificate: a bad certificate fails before any request', async () => {
  const v = await fake(APPROLE_ROUTES, { jwt: JWT_ROLE });
  try {
    const missing = path.join(tmp, 'no-such.pem');
    const out = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', 'process.exit(0)'], { env: certEnv(v.addr, { VAULT_CLIENT_CERTIFICATE_PATH: missing }) });
    assert.equal(out.status, 78);
    assert.equal(String(out.stderr), `[vault-env-loader] Cannot read the client certificate file (${missing}): ENOENT.\n`);
    const enc = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', 'process.exit(0)'], { env: certEnv(v.addr, { VAULT_CLIENT_CERTIFICATE_PATH: path.join(FIXTURES, 'encrypted.pem'), VAULT_CLIENT_CERTIFICATE_PASSWORD: 'wrong' }) });
    assert.equal(enc.status, 78);
    assert.match(String(enc.stderr), /wrong password/);
    assert.ok(!String(enc.stderr).includes('BEGIN'), 'no file contents in messages');
    assert.deepEqual(await v.requests(), []);
  } finally {
    v.stop();
  }
});

test('certificate: 503 and timeouts are retried, each time with a new assertion', async () => {
  const v = await fake(Object.assign({}, APPROLE_ROUTES, { 'auth/jwt/login': [{ status: 503, body: { errors: [] } }, { hang: true }, { status: 500, body: { errors: [] } }, { verify: true }] }), { jwt: JWT_ROLE });
  try {
    const env = certEnv(v.addr, { VAULT_ENV_TIMEOUT: '0.3' });
    await lib.load(Object.assign({ env }, FAST));
    assert.equal(env.DB_PASSWORD, 's3cr3t');
    const jtis = logins(await v.requests()).map((r) => r.body.assertion.claims.jti);
    assert.equal(jtis.length, 4);
    assert.equal(new Set(jtis).size, 4, 'a new jti for every attempt');
  } finally {
    v.stop();
  }
  const down = await fake(Object.assign({}, APPROLE_ROUTES, { 'auth/jwt/login': { status: 502, body: { errors: [] } } }), { jwt: JWT_ROLE });
  try {
    await rejectsCode(lib.load(Object.assign({ env: certEnv(down.addr, { VAULT_ENV_RETRIES: '2' }) }, FAST)), 'unavailable');
    assert.equal(logins(await down.requests()).length, 3, 'bounded by VAULT_ENV_RETRIES');
  } finally {
    down.stop();
  }
});

test('certificate: the CLI wrapper removes only the variables it used; the files stay', async () => {
  const v = await fake(APPROLE_ROUTES, { jwt: { role: 'role-123', certificate: certOf(path.join(FIXTURES, 'encrypted.pem')) } });
  try {
    const pw = path.join(tmp, 'cert-password');
    fs.writeFileSync(pw, 'fixture-password\n');
    const roleFile = path.join(tmp, 'unused-role-id-2');
    fs.writeFileSync(roleFile, 'other');
    const names = ['DB_PASSWORD', 'VAULT_ROLE_ID', 'VAULT_ROLE_ID_FILE', 'VAULT_CLIENT_CERTIFICATE_PATH', 'VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE', 'VAULT_ENV_JWT_MOUNT', 'VAULT_TOKEN'];
    const print = `process.stdout.write(JSON.stringify(Object.fromEntries(${JSON.stringify(names)}.map((k) => [k, process.env[k] || null]))))`;
    const env = certEnv(v.addr, { VAULT_CLIENT_CERTIFICATE_PATH: path.join(FIXTURES, 'encrypted.pem'), VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE: pw, VAULT_ROLE_ID_FILE: roleFile, VAULT_ENV_JWT_MOUNT: 'jwt' });
    const out = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', print], { env });
    assert.equal(out.status, 0, String(out.stderr));
    assert.deepEqual(JSON.parse(out.stdout), {
      DB_PASSWORD: 's3cr3t', VAULT_ROLE_ID: null, VAULT_ROLE_ID_FILE: roleFile, VAULT_CLIENT_CERTIFICATE_PATH: null,
      VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE: null, VAULT_ENV_JWT_MOUNT: 'jwt', VAULT_TOKEN: null,
    });
    assert.ok(fs.existsSync(pw));
    assert.equal((await v.requests()).pop().path, 'auth/token/revoke-self', 'revoked before the command ran');
  } finally {
    v.stop();
  }
});

test('certificate: --keep-token leaves the variables for the application', async () => {
  const v = await fake(APPROLE_ROUTES, { jwt: JWT_ROLE });
  try {
    const out = spawnSync(process.execPath, [INDEX, '--keep-token', '--', process.execPath, '-e', 'process.stdout.write(process.env.VAULT_CLIENT_CERTIFICATE_PATH + "|" + (process.env.VAULT_TOKEN || ""))'], { env: certEnv(v.addr) });
    assert.equal(out.status, 0, String(out.stderr));
    assert.equal(String(out.stdout), `${RSA_PEM}|`, 'the session token never reaches the command');
  } finally {
    v.stop();
  }
});

test('certificate: a secret ID beside the certificate is a configuration error, no request', async () => {
  const v = await fake(APPROLE_ROUTES, { jwt: JWT_ROLE });
  try {
    const out = spawnSync(process.execPath, [INDEX, '--', 'true'], { env: certEnv(v.addr, { VAULT_SECRET_ID: 's' }) });
    assert.equal(out.status, 78);
    assert.match(String(out.stderr), /AppRole login takes one or the other/);
    assert.deepEqual(await v.requests(), []);
  } finally {
    v.stop();
  }
});

test('certificate: the command-line flags, and no flag for the password', async () => {
  const v = await fake(APPROLE_ROUTES, { jwt: Object.assign({ mount: 'ci/jwt' }, JWT_ROLE) });
  try {
    const env = certEnv(v.addr);
    delete env.VAULT_CLIENT_CERTIFICATE_PATH;
    const out = spawnSync(process.execPath, [INDEX, '--client-certificate-path', RSA_PEM, '--client-key-path', RSA_PEM, '--jwt-mount', 'ci/jwt', '--', process.execPath, '-e', 'process.stdout.write(process.env.DB_PASSWORD)'], { env });
    assert.equal(out.status, 0, String(out.stderr));
    assert.equal(String(out.stdout), 's3cr3t');
  } finally {
    v.stop();
  }
  const bad = spawnSync(process.execPath, [INDEX, '--client-certificate-password', 'x', '--', 'true'], { env: {} });
  assert.equal(bad.status, 78);
  assert.match(String(bad.stderr), /no --client-certificate-password option/);
});

test('certificate: loadSync() logs in inside the worker; the session never reaches the parent', async () => {
  const v = await fake(APPROLE_ROUTES, { jwt: JWT_ROLE });
  try {
    const print = 'process.stdout.write(JSON.stringify({ DB_PASSWORD: process.env.DB_PASSWORD, T: process.env.VAULT_TOKEN || null, C: process.env.VAULT_CLIENT_CERTIFICATE_PATH || null }))';
    const out = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(INDEX)}).loadSync(); ${print}`], { env: certEnv(v.addr) });
    assert.equal(out.status, 0, String(out.stderr));
    assert.deepEqual(JSON.parse(out.stdout), { DB_PASSWORD: 's3cr3t', T: null, C: null });
    assert.equal((await v.requests()).pop().path, 'auth/token/revoke-self');
  } finally {
    v.stop();
  }
});

test('certificate: check names the method, the certificate and its expiry, and revokes', async () => {
  const v = await fake(APPROLE_ROUTES, { jwt: JWT_ROLE });
  try {
    const out = spawnSync(process.execPath, [INDEX, 'check'], { env: certEnv(v.addr) });
    assert.equal(out.status, 0, String(out.stderr));
    const days = Math.floor((Date.parse('2060-01-01T00:00:00Z') / 1000 - Date.now() / 1000) / 86400);
    assert.ok(String(out.stdout).includes(`auth     certificate (role_id role-123..., cert TRPxIPG0..., expires 2060-01-01, ${days} days, mount jwt; session revoked after reading)\n`), String(out.stdout));
    assert.equal(String(out.stderr), '');
    assert.equal((await v.requests()).pop().path, 'auth/token/revoke-self');
  } finally {
    v.stop();
  }
});

test('certificate: a failed revoke only warns', async () => {
  const v = await fake(Object.assign({}, APPROLE_ROUTES, { 'auth/token/revoke-self': { status: 500, body: { errors: [] } } }), { jwt: JWT_ROLE });
  try {
    const env = certEnv(v.addr);
    const { stderr } = await captureStderr(() => lib.load(Object.assign({ env }, FAST)));
    assert.equal(env.DB_PASSWORD, 's3cr3t');
    assert.equal(stderr, '[vault-env-loader] Could not revoke the certificate login session (HTTP 500); it expires by itself.\n');
  } finally {
    v.stop();
  }
});

test('certificate: a token wins and the certificate variables are left alone', async () => {
  const v = await fake(ROUTES);
  try {
    const env = childEnv(v.addr, { VAULT_ROLE_ID: 'r', VAULT_CLIENT_CERTIFICATE_PATH: RSA_PEM });
    const { stderr } = await captureStderr(() => lib.load(Object.assign({ env }, FAST)));
    assert.equal(env.DB_PASSWORD, 's3cr3t');
    assert.equal(env.VAULT_CLIENT_CERTIFICATE_PATH, RSA_PEM);
    assert.equal(stderr, '[vault-env-loader] VAULT_TOKEN is set, so VAULT_ROLE_ID / VAULT_SECRET_ID / VAULT_CLIENT_CERTIFICATE_PATH are ignored.\n');
  } finally {
    v.stop();
  }
});

test('clientAssertion(): a JWT that a Vault JWT role accepts', async () => {
  const v = await fake(APPROLE_ROUTES, { jwt: JWT_ROLE });
  try {
    const jwt = lib.clientAssertion({ roleId: 'role-123', certificatePath: RSA_PEM, vaultAddr: `${v.addr}/` });
    assert.equal(typeof jwt, 'string');
    const res = await new Promise((resolve) => {
      const req = require('http').request(`${v.addr}/v1/auth/jwt/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' } }, (r) => {
        r.resume();
        r.on('end', () => resolve(r.statusCode));
      });
      req.end(JSON.stringify({ role: 'role-123', jwt }));
    });
    assert.equal(res, 200);
  } finally {
    v.stop();
  }
  assert.throws(() => lib.clientAssertion({ certificatePath: RSA_PEM, vaultAddr: 'https://v.example.com' }), (e) => e instanceof lib.VaultEnvError && /needs roleId/.test(e.message));
  assert.throws(() => lib.clientAssertion({ roleId: 'r', certificatePath: path.join(FIXTURES, 'encrypted.pem'), vaultAddr: 'https://v.example.com' }), (e) => e.code === 'config' && /is encrypted/.test(e.message));
  const jwt = lib.clientAssertion({ roleId: 'r', certificatePath: path.join(FIXTURES, 'encrypted.pem'), password: 'fixture-password', vaultAddr: 'https://V.example.com:443', mount: 'ci/jwt' });
  const claims = JSON.parse(Buffer.from(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  assert.equal(claims.aud, 'https://v.example.com/v1/auth/ci/jwt/login');
});

// ---------------------------------------------------------------------------
// VAULT_ENV_ENABLED

const LINE = (m) => `[vault-env-loader] ${m}\n`;
const OFF = 'VAULT_ENV_ENABLED is off; nothing loaded from Vault.';
const ON_UNCONFIGURED = 'VAULT_ENV_ENABLED is on, but VAULT_ADDR and VAULT_ENV_IMPORT are not set.';
const BAD_SWITCH = 'VAULT_ENV_ENABLED must be true or false (or 1/0, yes/no, on/off).';

function unconfiguredEnv(extra) {
  const env = Object.assign({}, process.env);
  for (const k of Object.keys(env)) if (k.startsWith('VAULT_')) delete env[k];
  delete env.NODE_TEST_CONTEXT;
  return Object.assign(env, extra);
}

test('switched off: load() reads nothing, removes the token, does not mark the environment loaded', async () => {
  const v = await fake(ROUTES);
  try {
    const env = baseEnv(v.addr, { VAULT_ENV_IMPORT: 'database', VAULT_ENV_ENABLED: 'false' });
    const { value, stderr } = await captureStderr(() => lib.load(Object.assign({ env }, FAST)));
    assert.deepEqual(value, []);
    assert.equal(stderr, LINE(OFF));
    assert.equal(env.VAULT_TOKEN, undefined);
    assert.equal(env.VAULT_ENV_LOADED, undefined);
    assert.equal(env.VAULT_ADDR, v.addr, 'only credentials are removed');
    assert.deepEqual(await v.requests(), []);
  } finally {
    v.stop();
  }
});

test('switched off: fetch() returns nothing and leaves the environment alone', async () => {
  const env = { VAULT_ADDR: 'https://vault.example.com', VAULT_TOKEN: 't', VAULT_ENV_IMPORT: 'db', VAULT_ENV_ENABLED: 'off' };
  const { value, stderr } = await captureStderr(() => lib.fetch({ env }));
  assert.deepEqual(value, {});
  assert.equal(stderr, LINE(OFF));
  assert.equal(env.VAULT_TOKEN, 't');
});

test('switched off: loadSync(), -r and --import run the application without a fetch process or a request', async () => {
  const v = await fake(ROUTES);
  try {
    const entry = path.join(tmp, 'entry-off.mjs');
    fs.writeFileSync(entry, PRINT_ENV);
    const runs = [
      ['-e', `require(${JSON.stringify(INDEX)}).loadSync(); ${PRINT_ENV}`],
      ['-r', REGISTER_CJS, '-e', PRINT_ENV],
      ['--import', require('url').pathToFileURL(REGISTER_MJS).href, entry],
    ];
    for (const args of runs) {
      const out = spawnSync(process.execPath, args, { env: childEnv(v.addr, { VAULT_ENV_ENABLED: '0' }) });
      assert.equal(out.status, 0, String(out.stderr));
      assert.deepEqual(JSON.parse(out.stdout), { VAULT_TOKEN: null, LOADED: null }, args[0]);
      assert.equal(String(out.stderr), LINE(OFF), args[0]);
    }
    assert.deepEqual(await v.requests(), []);
  } finally {
    v.stop();
  }
});

test('switched off: the CLI runs the command without the token and passes its exit code through', async () => {
  const v = await fake(ROUTES);
  try {
    const out = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', `${PRINT_ENV}; process.exit(3)`], { env: childEnv(v.addr, { VAULT_ENV_ENABLED: 'No' }) });
    assert.equal(out.status, 3, String(out.stderr));
    assert.deepEqual(JSON.parse(out.stdout), { VAULT_TOKEN: null, LOADED: null });
    assert.equal(String(out.stderr), LINE(OFF));
    assert.deepEqual(await v.requests(), []);
  } finally {
    v.stop();
  }
});

test('switched off: VAULT_ENV_KEEP_TOKEN keeps the credentials; AppRole variables are removed like after a load', () => {
  const kept = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', PRINT_ENV], {
    env: unconfiguredEnv({ VAULT_ENV_ENABLED: 'false', VAULT_TOKEN: TOKEN, VAULT_ENV_KEEP_TOKEN: 'true' }),
  });
  assert.equal(kept.status, 0, String(kept.stderr));
  assert.equal(JSON.parse(kept.stdout).VAULT_TOKEN, TOKEN);
  const print = 'process.stdout.write(JSON.stringify([process.env.VAULT_ROLE_ID || null, process.env.VAULT_SECRET_ID_FILE || null, process.env.VAULT_ADDR || null]))';
  const role = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', print], {
    env: unconfiguredEnv({ VAULT_ENV_ENABLED: 'false', VAULT_ADDR: 'https://vault.example.com', VAULT_ROLE_ID: 'r', VAULT_SECRET_ID_FILE: '/nonexistent/secret-id' }),
  });
  assert.equal(role.status, 0, String(role.stderr));
  assert.deepEqual(JSON.parse(role.stdout), [null, null, 'https://vault.example.com']);
});

test('switched off: check says so, exit 0, no request', async () => {
  const v = await fake(ROUTES);
  try {
    const out = spawnSync(process.execPath, [INDEX, 'check'], { env: childEnv(v.addr, { VAULT_ENV_ENABLED: 'false' }) });
    assert.equal(out.status, 0, String(out.stderr));
    assert.equal(String(out.stdout), `${OFF}\n`);
    assert.equal(String(out.stderr), '');
    assert.deepEqual(await v.requests(), []);
  } finally {
    v.stop();
  }
});

test('switched on: loads as usual when configured, exit 78 when not', async () => {
  const v = await fake(ROUTES);
  try {
    const out = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', PRINT_ENV], { env: childEnv(v.addr, { VAULT_ENV_ENABLED: 'true' }) });
    assert.equal(out.status, 0, String(out.stderr));
    assert.deepEqual(JSON.parse(out.stdout), { DB_PASSWORD: 's3cr3t', VAULT_TOKEN: null, LOADED: '1' });
  } finally {
    v.stop();
  }
  for (const args of [['--', process.execPath, '-e', 'console.log("app ran")'], ['check']]) {
    const out = spawnSync(process.execPath, [INDEX, ...args], { env: unconfiguredEnv({ VAULT_ENV_ENABLED: 'on', VAULT_TOKEN: TOKEN }) });
    assert.equal(out.status, 78, args[0]);
    assert.equal(String(out.stdout), '');
    assert.equal(String(out.stderr), LINE(ON_UNCONFIGURED));
  }
  const reg = spawnSync(process.execPath, ['-r', REGISTER_CJS, '-e', 'console.log("app ran")'], { env: unconfiguredEnv({ VAULT_ENV_ENABLED: 'yes' }) });
  assert.equal(reg.status, 78);
  assert.equal(String(reg.stdout), '');
  assert.equal(String(reg.stderr), LINE(ON_UNCONFIGURED));
  await rejectsCode(lib.load({ env: { VAULT_ENV_ENABLED: '1' } }), 'config');
});

test('a value that is neither on nor off fails with exit 78 and reads nothing', async () => {
  const v = await fake(ROUTES);
  try {
    for (const args of [['--', process.execPath, '-e', 'console.log("app ran")'], ['check']]) {
      const out = spawnSync(process.execPath, [INDEX, ...args], { env: childEnv(v.addr, { VAULT_ENV_ENABLED: 'ture' }) });
      assert.equal(out.status, 78, args[0]);
      assert.equal(String(out.stdout), '');
      assert.equal(String(out.stderr), LINE(BAD_SWITCH));
    }
    assert.deepEqual(await v.requests(), []);
  } finally {
    v.stop();
  }
});

test('VAULT_SKIP_VERIFY is refused even when switched off', () => {
  const out = spawnSync(process.execPath, [INDEX, '--', process.execPath, '-e', 'console.log("app ran")'], {
    env: unconfiguredEnv({ VAULT_ENV_ENABLED: 'false', VAULT_SKIP_VERIFY: 'true' }),
  });
  assert.equal(out.status, 78);
  assert.equal(String(out.stdout), '');
  assert.match(String(out.stderr), /VAULT_SKIP_VERIFY is set/);
});

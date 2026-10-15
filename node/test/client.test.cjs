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

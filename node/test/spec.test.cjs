'use strict';
// Runs the shared conformance cases in ../../spec/cases.json.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const { _internal: I, VaultEnvError } = require('../index.cjs');

const cases = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'spec', 'cases.json'), 'utf8'));

const codeOf = (fn) => {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof VaultEnvError, `expected VaultEnvError, got ${e}`);
    return e.code;
  }
  return null;
};

test('envName', () => {
  for (const c of cases.envName) assert.equal(I.envName(c.key, c.mode), c.expect, `${c.key} (${c.mode})`);
});

test('mapEntries', () => {
  for (const c of cases.mapEntries) {
    const imp = { raw: 'test', prefix: c.prefix, name: c.mode };
    if (c.error) {
      assert.equal(codeOf(() => I.mapEntries(c.data, imp, Boolean(c.caseInsensitive))), c.error, c.name);
    } else {
      const got = Object.fromEntries(I.mapEntries(c.data, imp, Boolean(c.caseInsensitive)).map((e) => [e.name, e.value]));
      assert.deepEqual(got, c.expect, c.name);
    }
  }
});

test('mergeImports', () => {
  for (const c of cases.merge) {
    const results = c.imports.map((m) => ({ entries: Object.keys(m).map((k) => ({ key: k, name: k, value: m[k] })) }));
    const got = I.mergeImports(results, Boolean(c.caseInsensitive));
    assert.deepEqual(got.values, c.expect, c.name);
    assert.deepEqual(got.overridden, c.overridden, c.name);
  }
});

test('plan', () => {
  for (const c of cases.plan) {
    const got = I.plan(c.values, c.env, c.override);
    assert.deepEqual(got.set, c.set, c.name);
    assert.deepEqual(got.kept, c.kept, c.name);
  }
});

test('parseImport', () => {
  for (const c of cases.parseImport) {
    if (c.error) {
      assert.equal(codeOf(() => I.parseImport(c.raw)), c.error, c.raw);
      continue;
    }
    const got = I.parseImport(c.raw);
    for (const k of Object.keys(c.expect)) assert.deepEqual(got[k], c.expect[k], `${c.raw}: ${k}`);
  }
});

test('authSelection', () => {
  const os = require('os');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vel-spec-'));
  let n = 0;
  for (const c of cases.authSelection) {
    if (!c.name) continue; // the section's $comment
    const env = { VAULT_ADDR: 'https://vault.example.com', VAULT_ENV_IMPORT: 'db' };
    for (const [k, v] of Object.entries(c.env)) {
      const m = /^<file:([\s\S]*)>$/.exec(v);
      if (m) {
        const file = path.join(dir, `f${n++}`);
        fs.writeFileSync(file, m[1]);
        env[k] = file;
      } else env[k] = v;
    }
    if (c.error) {
      assert.equal(codeOf(() => I.readConfig({}, env)), c.error, c.name);
      if (c.message) assert.throws(() => I.readConfig({}, env), (err) => err.message === c.message, c.name);
      continue;
    }
    const cfg = I.readConfig({}, env);
    const e = c.expect;
    const orNull = (v) => (v === undefined ? null : v);
    if ('certificatePath' in e) assert.equal(orNull(cfg.certificatePath), e.certificatePath, c.name);
    if ('keyPath' in e) assert.equal(orNull(cfg.keyPath), e.keyPath, c.name);
    if ('password' in e) assert.equal(orNull(cfg.password), e.password, c.name);
    if ('jwtMount' in e) assert.equal(cfg.jwtMount, e.jwtMount, c.name);
    if ('note' in e) assert.deepEqual(cfg.notes, [e.note], c.name);
    assert.equal(cfg.auth, e.auth, c.name);
    if ('roleId' in e) assert.equal(cfg.roleId, e.roleId, c.name);
    if ('secretId' in e) assert.equal(cfg.secretId === undefined ? null : cfg.secretId, e.secretId, c.name);
    if ('mount' in e) assert.equal(cfg.approleMount, e.mount, c.name);
    if ('used' in e) assert.deepEqual(cfg.appRoleVarsUsed, e.used, c.name);
    if ('ignoredNote' in e) assert.equal(cfg.notes.some((s) => /ignored/.test(s)), e.ignoredNote, c.name);
  }
});

test('enabledSwitch', () => {
  for (const c of cases.enabledSwitch) {
    if (!c.name) continue; // the section's $comment
    const env = Object.assign({}, c.env);
    if (c.error) {
      let err;
      try {
        I.readConfig({}, env);
      } catch (e) {
        err = e;
      }
      assert.ok(err instanceof VaultEnvError, `${c.name}: expected VaultEnvError, got ${err}`);
      assert.equal(err.code, c.error, c.name);
      assert.equal(err.message, c.message, c.name);
      continue;
    }
    const cfg = I.readConfig({}, env);
    const state = cfg.disabled ? 'disabled' : cfg.configured ? 'configured' : 'unconfigured';
    assert.equal(state, c.expect.state, c.name);
    if (state !== 'disabled') continue;
    I.stripCredentials(env, cfg);
    const removed = Object.keys(c.env).filter((k) => !(k in env)).sort();
    assert.deepEqual(removed, c.expect.removed.slice().sort(), c.name);
    assert.equal(env.VAULT_ENV_LOADED, undefined, c.name);
  }
});

// ---------------------------------------------------------------------------
// Certificate login (0.4)

const FIXTURES = path.join(__dirname, '..', '..', 'spec', 'fixtures');
const crypto = require('crypto');
const fromB64url = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

test('audience', () => {
  for (const c of cases.audience) {
    if (!c.addr) continue;
    assert.equal(I.audience(c.addr, c.mount), c.expect, c.addr);
  }
});

test('certificates', () => {
  for (const c of cases.certificates) {
    if (!c.name) continue;
    const load = () => I.loadClientCertificate(path.join(FIXTURES, c.file), c.keyFile && path.join(FIXTURES, c.keyFile), c.password);
    if (c.error) {
      assert.throws(load, (e) => e instanceof VaultEnvError && e.code === c.error && e.message.includes(c.message), c.name);
      continue;
    }
    const cred = load();
    assert.equal(cred.alg, c.expect.alg, c.name);
    if (c.expect.x5t) assert.equal(cred.x5t, c.expect.x5t, c.name);
    if (c.expect.notAfter) assert.equal(new Date(cred.notAfter * 1000).toISOString().replace('.000Z', 'Z'), c.expect.notAfter, c.name);
  }
});

test('the DER walk agrees with X509Certificate', { skip: !crypto.X509Certificate && 'no X509Certificate before Node 15.6' }, () => {
  for (const f of fs.readdirSync(FIXTURES)) {
    const text = fs.readFileSync(path.join(FIXTURES, f), 'latin1');
    const m = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(text);
    if (!m) continue;
    const x = new crypto.X509Certificate(m[0]);
    const got = I.parseCertificateDer(x.raw);
    assert.equal(got.notAfter * 1000, Date.parse(x.validTo), f);
    assert.ok(got.spki.equals(x.publicKey.export({ type: 'spki', format: 'der' })), f);
  }
});

test('assertion: header, claims, lifetime, signature, a new jti every time', () => {
  const a = cases.assertion;
  for (const c of cases.certificates) {
    if (!c.name || c.error || !c.expect.x5t) continue;
    const cred = I.loadClientCertificate(path.join(FIXTURES, c.file), c.keyFile && path.join(FIXTURES, c.keyFile), c.password);
    const aud = 'https://vault.example.com/v1/auth/jwt/login';
    const jwt = I.signAssertion(cred, 'role-1', aud, 1800000000);
    const [h, p, sig] = jwt.split('.');
    assert.ok([h, p, sig].every((x) => /^[A-Za-z0-9_-]+$/.test(x)), 'base64url without padding');
    const header = JSON.parse(fromB64url(h));
    const claims = JSON.parse(fromB64url(p));
    assert.deepEqual(Object.keys(header), a.header.fields, c.name);
    assert.deepEqual(header, { alg: c.expect.alg, typ: a.header.typ, 'x5t#S256': c.expect.x5t }, c.name);
    assert.deepEqual(Object.keys(claims), a.claims, c.name);
    assert.equal(claims.iss, 'role-1');
    assert.equal(claims.sub, 'role-1');
    assert.equal(claims.aud, aud);
    assert.equal(claims.iat, 1800000000);
    assert.equal(claims.exp - claims.iat, a.lifetime);
    assert.match(claims.jti, /^[0-9a-f]{32}$/);
    assert.notEqual(JSON.parse(fromB64url(I.signAssertion(cred, 'role-1', aud).split('.')[1])).jti, claims.jti);
    const certPem = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(fs.readFileSync(path.join(FIXTURES, c.file), 'latin1'))[0];
    const pub = crypto.createPublicKey(certPem);
    const data = Buffer.from(`${h}.${p}`);
    const raw = fromB64url(sig);
    const ok = c.expect.alg === 'RS256'
      ? crypto.verify('sha256', data, pub, raw)
      : (assert.equal(raw.length, c.expect.alg === 'ES256' ? 64 : 96), crypto.verify(c.expect.alg === 'ES256' ? 'sha256' : 'sha384', data, { key: pub, dsaEncoding: 'ieee-p1363' }, raw));
    assert.ok(ok, `${c.name}: signature`);
  }
});

test('certificateStatus', () => {
  for (const c of cases.certificateStatus) {
    if (!c.now) continue;
    const st = I.certificateStatus(Date.parse(c.notAfter) / 1000, Date.parse(c.now) / 1000);
    assert.equal(st.days, c.expect.days, c.notAfter);
    assert.equal(st.warning, c.expect.warning, c.notAfter);
    if (c.expect.checkLine) assert.equal(I.certificateCheckLine('7f3c2a1e-0000-4000-8000-000000000000', 'q3Z1Ab12cdEF', st, 'jwt'), c.expect.checkLine, c.notAfter);
  }
});

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
      const m = /^<file:(.*)>$/.exec(v);
      if (m) {
        const file = path.join(dir, `f${n++}`);
        fs.writeFileSync(file, m[1]);
        env[k] = file;
      } else env[k] = v;
    }
    if (c.error) {
      assert.equal(codeOf(() => I.readConfig({}, env)), c.error, c.name);
      continue;
    }
    const cfg = I.readConfig({}, env);
    const e = c.expect;
    assert.equal(cfg.auth, e.auth, c.name);
    if ('roleId' in e) assert.equal(cfg.roleId, e.roleId, c.name);
    if ('secretId' in e) assert.equal(cfg.secretId === undefined ? null : cfg.secretId, e.secretId, c.name);
    if ('mount' in e) assert.equal(cfg.approleMount, e.mount, c.name);
    if ('used' in e) assert.deepEqual(cfg.appRoleVarsUsed, e.used, c.name);
    if ('ignoredNote' in e) assert.equal(cfg.notes.some((s) => /ignored/.test(s)), e.ignoredNote, c.name);
  }
});

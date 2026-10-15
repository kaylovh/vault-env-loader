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

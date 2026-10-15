#!/usr/bin/env node
'use strict';
/*
 * vault-env-loader — load HashiCorp Vault KV secrets into environment
 * variables before your application starts.
 *
 * One file, zero dependencies, Node >= 14. It is at the same time:
 *   - the CLI:   vault-env-loader [options] -- <command...>
 *   - the library: load() / loadSync() / fetch()
 *   - the worker loadSync() runs in a child process (--internal-fetch)
 *
 * Secret values never go to logs, error messages, argv or disk.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const tls = require('tls');
const childProcess = require('child_process');

const VERSION = '0.1.0';
const TAG = '[vault-env-loader]';
const EX_CONFIG = 78;
const LOADED_MARK = 'VAULT_ENV_LOADED';
const TTL_WARN_SECONDS = 14 * 24 * 3600;
// Linux MAX_ARG_STRLEN: one "NAME=value\0" string handed to execve.
const MAX_ENV_STRING = 128 * 1024;
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
const VALID_ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const NAME_MODES = ['auto', 'verbatim', 'upper'];
// Some Vault-compatible servers that resolve keys from other stores answer 502
// with "alias 'x' could not be resolved: <reason>" per failed key.
const TRANSIENT_ALIAS_REASONS = ['timeout', 'unavailable'];

class VaultEnvError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'VaultEnvError';
    this.code = code || 'error';
  }
}

function warn(message) {
  process.stderr.write(`${TAG} ${message}\n`);
}

function truthy(v) {
  return typeof v === 'string' && ['1', 'true', 'yes', 'on'].includes(v.trim().toLowerCase());
}

function nonEmpty(v) {
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined;
}

// ---------------------------------------------------------------------------
// Configuration

function readConfig(options, env) {
  options = options || {};
  env = env || process.env;
  const pick = (opt, ...names) => {
    if (options[opt] !== undefined && options[opt] !== null) return options[opt];
    for (const n of names) if (nonEmpty(env[n]) !== undefined) return env[n];
    return undefined;
  };

  const skip = nonEmpty(env.VAULT_SKIP_VERIFY);
  if (skip !== undefined && !['0', 'false', 'no', 'off'].includes(skip.toLowerCase())) {
    throw new VaultEnvError('VAULT_SKIP_VERIFY is set, but vault-env-loader never skips TLS verification. Unset it and point VAULT_CACERT at your CA instead.', 'config');
  }

  const addr = nonEmpty(pick('addr', 'VAULT_ADDR'));
  let imports = pick('imports', 'VAULT_ENV_IMPORT');
  if (typeof imports === 'string') imports = splitList(imports);
  imports = (imports || []).map((s) => String(s).trim()).filter(Boolean);

  const tokenFile = nonEmpty(pick('tokenFile', 'VAULT_TOKEN_FILE'));
  let token = options.token !== undefined ? options.token : nonEmpty(env.VAULT_TOKEN);

  const configured = Boolean(addr || imports.length);
  if (!configured) return { configured: false };

  if (!addr) throw new VaultEnvError('VAULT_ADDR is not set (VAULT_ENV_IMPORT is).', 'config');
  if (!imports.length) throw new VaultEnvError('VAULT_ENV_IMPORT is empty: name at least one path to load.', 'config');
  if (!token && tokenFile) {
    try {
      token = fs.readFileSync(tokenFile, 'utf8').trim();
    } catch (e) {
      throw new VaultEnvError(`Cannot read VAULT_TOKEN_FILE (${tokenFile}): ${e.code || 'error'}.`, 'config');
    }
    if (!token) throw new VaultEnvError(`VAULT_TOKEN_FILE (${tokenFile}) is empty.`, 'config');
  }
  if (!token) throw new VaultEnvError('No token: set VAULT_TOKEN or VAULT_TOKEN_FILE.', 'config');

  let url;
  try {
    url = new URL(addr);
  } catch (e) {
    throw new VaultEnvError('VAULT_ADDR is not a valid URL.', 'config');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new VaultEnvError('VAULT_ADDR must start with https://', 'config');
  const allowHttp = options.allowHttp !== undefined ? Boolean(options.allowHttp) : truthy(env.VAULT_ENV_ALLOW_HTTP);
  if (url.protocol === 'http:' && !isLoopback(url.hostname)) {
    if (!allowHttp) throw new VaultEnvError(`VAULT_ADDR uses plain http to ${url.hostname}; use https, or set VAULT_ENV_ALLOW_HTTP=true if this network really has no TLS.`, 'config');
  }

  const num = (v, def, name) => {
    if (v === undefined || v === null || v === '') return def;
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0) throw new VaultEnvError(`${name} must be a non-negative number.`, 'config');
    return n;
  };

  return {
    configured: true,
    addr: url.toString().replace(/\/+$/, ''),
    insecureHttp: url.protocol === 'http:' && !isLoopback(url.hostname),
    token,
    tokenFromFile: !nonEmpty(env.VAULT_TOKEN) && options.token === undefined && Boolean(tokenFile),
    namespace: nonEmpty(pick('namespace', 'VAULT_NAMESPACE')),
    ca: loadCa(nonEmpty(pick('cacert', 'VAULT_CACERT')), nonEmpty(pick('capath', 'VAULT_CAPATH'))),
    imports: imports.map(parseImport),
    base: nonEmpty(pick('base', 'VAULT_ENV_BASE')),
    override: options.override !== undefined ? Boolean(options.override) : truthy(env.VAULT_ENV_OVERRIDE),
    keepToken: options.keepToken !== undefined ? Boolean(options.keepToken) : truthy(env.VAULT_ENV_KEEP_TOKEN),
    timeoutMs: num(pick('timeout', 'VAULT_ENV_TIMEOUT'), 10, 'VAULT_ENV_TIMEOUT') * 1000,
    retries: Math.floor(num(pick('retries', 'VAULT_ENV_RETRIES'), 3, 'VAULT_ENV_RETRIES')),
    retryDelayMs: options.retryDelayMs !== undefined ? options.retryDelayMs : 1000,
    caseInsensitive: options.caseInsensitive !== undefined ? Boolean(options.caseInsensitive) : process.platform === 'win32',
  };
}

function isLoopback(host) {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
}

function splitList(s) {
  return s.split(/[,\n]/);
}

function loadCa(file, dir) {
  const extra = [];
  if (file) {
    try {
      extra.push(fs.readFileSync(file, 'utf8'));
    } catch (e) {
      throw new VaultEnvError(`Cannot read VAULT_CACERT (${file}): ${e.code || 'error'}.`, 'config');
    }
  }
  if (dir) {
    let names;
    try {
      names = fs.readdirSync(dir);
    } catch (e) {
      throw new VaultEnvError(`Cannot read VAULT_CAPATH (${dir}): ${e.code || 'error'}.`, 'config');
    }
    for (const n of names) if (/\.(pem|crt)$/i.test(n)) extra.push(fs.readFileSync(path.join(dir, n), 'utf8'));
  }
  if (!extra.length) return undefined;
  return (tls.rootCertificates || []).concat(extra);
}

// ---------------------------------------------------------------------------
// Imports:  [optional:]location[?prefix=..&name=auto|verbatim|upper&kv=1|2]
//   vault://<mount>/<path>   absolute (same as Spring Cloud Vault)
//   vault://                 the base path itself
//   <path>                   relative to the base path

function parseImport(raw) {
  let spec = raw.trim();
  let optional = false;
  if (spec.startsWith('optional:')) {
    optional = true;
    spec = spec.slice('optional:'.length).trim();
  }
  let query = '';
  const q = spec.indexOf('?');
  if (q >= 0) {
    query = spec.slice(q + 1);
    spec = spec.slice(0, q);
  }
  const opts = { prefix: '', name: 'auto', kv: undefined };
  if (query) {
    for (const part of query.split('&')) {
      if (!part) continue;
      const eq = part.indexOf('=');
      const k = decodeURIComponent(eq >= 0 ? part.slice(0, eq) : part);
      const v = decodeURIComponent(eq >= 0 ? part.slice(eq + 1) : '');
      if (k === 'prefix') opts.prefix = v;
      else if (k === 'name') {
        if (!NAME_MODES.includes(v)) throw new VaultEnvError(`Import "${raw}": name must be one of ${NAME_MODES.join(', ')}.`, 'config');
        opts.name = v;
      } else if (k === 'kv') {
        if (v !== '1' && v !== '2') throw new VaultEnvError(`Import "${raw}": kv must be 1 or 2.`, 'config');
        opts.kv = Number(v);
      } else throw new VaultEnvError(`Import "${raw}": unknown option "${k}" (known: prefix, name, kv).`, 'config');
    }
  }
  if (opts.name !== 'verbatim' && !/^[A-Za-z0-9_]*$/.test(opts.prefix)) {
    throw new VaultEnvError(`Import "${raw}": prefix may only contain letters, digits and _.`, 'config');
  }

  let kind;
  let p;
  if (spec === 'vault://' || spec === 'vault:') {
    kind = 'base';
    p = '';
  } else if (spec.startsWith('vault://')) {
    kind = 'absolute';
    p = spec.slice('vault://'.length);
  } else if (spec.includes('://')) {
    throw new VaultEnvError(`Import "${raw}": only vault:// locations are supported.`, 'config');
  } else {
    kind = 'relative';
    p = spec;
  }
  p = p.replace(/^\/+|\/+$/g, '');
  if (kind !== 'base' && !p) throw new VaultEnvError(`Import "${raw}": empty path.`, 'config');
  if (p && p.split('/').some((s) => s === '' || s === '.' || s === '..')) {
    throw new VaultEnvError(`Import "${raw}": path segments may not be empty, "." or "..".`, 'config');
  }
  if (kind === 'absolute' && !p.includes('/')) throw new VaultEnvError(`Import "${raw}": expected vault://<mount>/<path>.`, 'config');
  return { raw, optional, kind, path: p, prefix: opts.prefix, name: opts.name, kv: opts.kv };
}

// ---------------------------------------------------------------------------
// HTTP

function encodePath(p) {
  return p.split('/').map(encodeURIComponent).join('/');
}

function httpGet(cfg, apiPath) {
  const url = new URL(`${cfg.addr}/v1/${apiPath}`);
  const lib = url.protocol === 'https:' ? https : http;
  const headers = {
    'X-Vault-Token': cfg.token,
    'X-Vault-Request': 'true',
    'User-Agent': `vault-env-loader/${VERSION} node/${process.versions.node}`,
    Accept: 'application/json',
  };
  if (cfg.namespace) headers['X-Vault-Namespace'] = cfg.namespace;
  return new Promise((resolve, reject) => {
    const req = lib.request(url, { method: 'GET', headers, ca: cfg.ca, agent: false }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_RESPONSE_BYTES) {
          req.destroy(new VaultEnvError('response too large', 'network'));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let body = null;
        try {
          body = text ? JSON.parse(text) : null;
        } catch (e) {
          body = null;
        }
        resolve({ status: res.statusCode, body });
      });
      res.on('error', reject);
    });
    req.setTimeout(cfg.timeoutMs, () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    req.on('error', reject);
    req.end();
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function aliasFailures(body) {
  const errors = body && Array.isArray(body.errors) ? body.errors : [];
  const out = [];
  for (const e of errors) {
    const m = /^alias '(.+)' could not be resolved: ([a-z_]+)$/.exec(String(e));
    if (m) out.push({ alias: m[1], reason: m[2] });
  }
  return out;
}

function retryable(res) {
  if ([429, 500, 503, 504].includes(res.status)) return true;
  if (res.status === 502) {
    const failures = aliasFailures(res.body);
    return !failures.length || failures.every((f) => TRANSIENT_ALIAS_REASONS.includes(f.reason));
  }
  return false;
}

// GET with retries on transient failures. Resolves with the final response;
// rejects only for network errors that outlived the retries.
async function getWithRetry(cfg, apiPath) {
  let attempt = 0;
  for (;;) {
    let res;
    let netErr;
    try {
      res = await httpGet(cfg, apiPath);
    } catch (e) {
      netErr = e;
    }
    if (res && !retryable(res)) return res;
    if (attempt >= cfg.retries) {
      if (res) return res;
      const what = netErr && netErr.code === 'ETIMEDOUT' ? 'timed out' : `failed (${(netErr && netErr.code) || 'network error'})`;
      throw new VaultEnvError(`Request to Vault ${what}.`, 'unavailable');
    }
    await sleep(cfg.retryDelayMs * Math.pow(2, attempt));
    attempt += 1;
  }
}

// ---------------------------------------------------------------------------
// Vault reads

async function lookupSelf(cfg) {
  const res = await getWithRetry(cfg, 'auth/token/lookup-self');
  if (res.status === 401 || res.status === 403) return { denied: true, ttl: 0, meta: {} };
  if (res.status !== 200 || !res.body || !res.body.data) return null;
  const d = res.body.data;
  return { ttl: typeof d.ttl === 'number' ? d.ttl : 0, meta: d.meta && typeof d.meta === 'object' ? d.meta : {} };
}

function resolveBase(cfg, self) {
  if (cfg.base) return { base: cfg.base.replace(/^\/+|\/+$/g, ''), source: 'VAULT_ENV_BASE' };
  const m = self && self.meta;
  if (m && nonEmpty(m.application) && nonEmpty(m.environment)) {
    return { base: `secret/${m.application}/${m.environment}`, source: 'token metadata', app: m.application, env: m.environment };
  }
  return { base: null, source: null, denied: Boolean(self && self.denied) };
}

function fullPath(imp, baseInfo) {
  if (imp.kind === 'absolute') {
    if (baseInfo.source === 'token metadata') {
      const seg = imp.path.split('/');
      if (seg[0] === 'secret' && (seg[1] !== baseInfo.app || seg[2] !== baseInfo.env)) {
        throw new VaultEnvError(
          `Import "${imp.raw}" points at ${seg[1] || '?'}/${seg[2] || '?'}, but this token belongs to ${baseInfo.app}/${baseInfo.env}. A token can only read its own application and environment.`,
          'config'
        );
      }
    }
    return imp.path;
  }
  if (!baseInfo.base) {
    if (baseInfo.denied) {
      throw new VaultEnvError(
        `Import "${imp.raw}" is relative, and Vault refused to describe the token (permission denied on auth/token/lookup-self): the token is invalid, expired or revoked, its IP is not allowed, or its policy lacks lookup-self. Set VAULT_ENV_BASE or write vault://<mount>/<path> if the policy is intended.`,
        'auth'
      );
    }
    throw new VaultEnvError(`Import "${imp.raw}" is relative, but there is no base path: set VAULT_ENV_BASE or write vault://<mount>/<path>.`, 'config');
  }
  return imp.kind === 'base' ? baseInfo.base : `${baseInfo.base}/${imp.path}`;
}

// Learn the mount and KV version the way `vault kv get` does.
async function locate(cfg, imp, p) {
  const firstSeg = p.split('/')[0];
  const fallback = { mount: firstSeg, rest: p.slice(firstSeg.length + 1), kv: imp.kv || 2, probed: false };
  if (imp.kv) return fallback;
  const res = await getWithRetry(cfg, `sys/internal/ui/mounts/${encodePath(p)}`);
  const d = res.status === 200 && res.body && res.body.data;
  if (!d) return fallback;
  const mount = typeof d.path === 'string' && d.path ? d.path.replace(/\/+$/, '') : firstSeg;
  if (p !== mount && !p.startsWith(`${mount}/`)) return fallback;
  const version = d.options && String(d.options.version) === '2' ? 2 : d.type === 'kv' || d.type === 'generic' ? 1 : 2;
  return { mount, rest: p.slice(mount.length + 1), kv: version, probed: true };
}

function describeStatus(res, imp, p, loc) {
  const where = `"${imp.raw}" (${p})`;
  if (res.status === 401 || res.status === 403) {
    return new VaultEnvError(`Permission denied reading ${where}: the token is invalid, expired or revoked, its IP is not allowed, or its policy does not allow reading this path.`, 'auth');
  }
  if (res.status === 404) {
    const hint = loc.probed ? '' : ` If this is a KV version ${loc.kv === 2 ? 1 : 2} mount, add ?kv=${loc.kv === 2 ? 1 : 2}.`;
    return new VaultEnvError(`Not found: ${where}.${hint}`, 'not_found');
  }
  const failures = res.status === 502 ? aliasFailures(res.body) : [];
  if (failures.length) {
    const list = failures.map((f) => `${f.alias} (${f.reason})`).join(', ');
    return new VaultEnvError(`Vault could not resolve ${where}: ${list}.`, 'resolve');
  }
  return new VaultEnvError(`Vault answered HTTP ${res.status} for ${where}.`, 'unavailable');
}

async function readImport(cfg, imp, baseInfo) {
  const p = fullPath(imp, baseInfo);
  const loc = await locate(cfg, imp, p);
  const apiPath = loc.kv === 2 ? `${encodePath(loc.mount)}/data/${encodePath(loc.rest)}` : encodePath(p);
  const res = await getWithRetry(cfg, apiPath);
  if (res.status === 200 && res.body && res.body.data) {
    const data = loc.kv === 2 ? res.body.data.data : res.body.data;
    const version = loc.kv === 2 && res.body.data.metadata ? res.body.data.metadata.version : undefined;
    if (data && typeof data === 'object') return { path: p, kv: loc.kv, version, data };
    // KV v2 answers 200 with data: null for a deleted latest version.
    if (loc.kv === 2) return { path: p, kv: loc.kv, missing: true };
  }
  if (res.status === 404 && imp.optional) return { path: p, kv: loc.kv, missing: true };
  throw describeStatus(res, imp, p, loc);
}

// ---------------------------------------------------------------------------
// Key -> environment variable names

function envName(key, mode) {
  if (mode === 'verbatim') return key;
  if (mode === 'auto' && VALID_ENV_NAME.test(key)) return key;
  let n = key.replace(/[^A-Za-z0-9_]/g, '_').toUpperCase();
  if (/^[0-9]/.test(n)) n = `_${n}`;
  return n;
}

function stringValue(v) {
  if (typeof v === 'string') return v;
  if (v === null || v === undefined) return '';
  return JSON.stringify(v);
}

// Map one import's data to [{key, name, value}], failing on collisions and on
// values an environment cannot carry. Errors name keys, never values.
function mapEntries(data, imp, caseInsensitive) {
  const entries = [];
  const seen = new Map();
  for (const key of Object.keys(data)) {
    const name = imp.prefix + envName(key, imp.name);
    if (!name || name.includes('=') || name.includes('\0')) {
      throw new VaultEnvError(`Key "${key}" in "${imp.raw}" cannot be used as an environment variable name; use ?name=auto or ?name=upper.`, 'value');
    }
    const cmp = caseInsensitive ? name.toUpperCase() : name;
    if (seen.has(cmp)) {
      throw new VaultEnvError(`Keys "${seen.get(cmp)}" and "${key}" in "${imp.raw}" both become ${name}. Rename one of them in Vault, or choose another ?name= mode.`, 'collision');
    }
    seen.set(cmp, key);
    const value = stringValue(data[key]);
    if (value.includes('\0')) throw new VaultEnvError(`The value of "${key}" in "${imp.raw}" contains a NUL byte, which an environment variable cannot hold.`, 'value');
    if (Buffer.byteLength(name) + 1 + Buffer.byteLength(value) + 1 > MAX_ENV_STRING) {
      throw new VaultEnvError(`The value of "${key}" in "${imp.raw}" is larger than 128 KB, the limit for one environment variable.`, 'value');
    }
    entries.push({ key, name, value });
  }
  return entries;
}

// Later imports win over earlier ones. Returns the merged map plus the names
// that were overridden (for a warning).
function mergeImports(results, caseInsensitive) {
  const values = {};
  const canonical = new Map();
  const overridden = [];
  for (const r of results) {
    for (const e of r.entries || []) {
      const cmp = caseInsensitive ? e.name.toUpperCase() : e.name;
      if (canonical.has(cmp)) {
        const prev = canonical.get(cmp);
        delete values[prev];
        if (!overridden.includes(e.name)) overridden.push(e.name);
      }
      canonical.set(cmp, e.name);
      values[e.name] = e.value;
    }
  }
  return { values, overridden };
}

// Decide what to write into env. Existing variables win unless override.
function plan(values, env, override) {
  const set = {};
  const kept = [];
  for (const name of Object.keys(values)) {
    if (!override && env[name] !== undefined) kept.push(name);
    else set[name] = values[name];
  }
  return { set, kept };
}

// ---------------------------------------------------------------------------
// Pipeline

async function collect(cfg) {
  const warnings = [];
  if (cfg.insecureHttp) warnings.push('VAULT_ADDR uses plain http: the token and every secret cross the network unencrypted.');
  const self = await lookupSelf(cfg);
  if (self && !self.denied && self.ttl > 0 && self.ttl < TTL_WARN_SECONDS) {
    warnings.push(`The token expires in ${Math.max(1, Math.round(self.ttl / 86400))} day(s). Issue a new one before then.`);
  }
  const baseInfo = resolveBase(cfg, self);
  const results = [];
  for (const imp of cfg.imports) {
    const r = await readImport(cfg, imp, baseInfo);
    if (r.missing) {
      if (!imp.optional) throw new VaultEnvError(`Not found: "${imp.raw}" (${r.path}).`, 'not_found');
      results.push({ raw: imp.raw, path: r.path, kv: r.kv, skipped: true, entries: [] });
      continue;
    }
    results.push({ raw: imp.raw, path: r.path, kv: r.kv, version: r.version, entries: mapEntries(r.data, imp, cfg.caseInsensitive) });
  }
  const merged = mergeImports(results, cfg.caseInsensitive);
  if (merged.overridden.length) warnings.push(`Set by more than one import (the later one wins): ${merged.overridden.join(', ')}.`);
  return { self, baseInfo, results, values: merged.values, warnings };
}

function report(result) {
  return {
    token: result.self && !result.self.denied ? { ttl: result.self.ttl, meta: result.self.meta } : null,
    base: result.baseInfo.base,
    baseSource: result.baseInfo.source,
    imports: result.results.map((r) => ({
      import: r.raw,
      path: r.path,
      kv: r.kv,
      version: r.version,
      skipped: Boolean(r.skipped),
      variables: r.entries.map((e) => ({ name: e.name, key: e.key, length: e.value.length })),
    })),
  };
}

function apply(values, env, cfg) {
  const { set, kept } = plan(values, env, cfg.override);
  for (const name of Object.keys(set)) env[name] = set[name];
  if (kept.length) warn(`Already set in the environment, kept as is (set VAULT_ENV_OVERRIDE=true to replace): ${kept.join(', ')}.`);
  env[LOADED_MARK] = '1';
  if (!cfg.keepToken) {
    delete env.VAULT_TOKEN;
    if (cfg.tokenFromFile) delete env.VAULT_TOKEN_FILE;
  }
  return Object.keys(set);
}

const NOT_CONFIGURED = 'VAULT_ADDR and VAULT_ENV_IMPORT are not set; nothing loaded from Vault.';

// ---------------------------------------------------------------------------
// Library API

/** Read the configured imports and return { NAME: value } without touching process.env. */
async function fetchValues(options) {
  const cfg = readConfig(options, (options && options.env) || process.env);
  if (!cfg.configured) throw new VaultEnvError(NOT_CONFIGURED, 'config');
  const result = await collect(cfg);
  result.warnings.forEach(warn);
  return result.values;
}

/** Load into process.env (async). Returns the names that were set. */
async function load(options) {
  const env = (options && options.env) || process.env;
  if (env[LOADED_MARK]) return [];
  const cfg = readConfig(options, env);
  if (!cfg.configured) {
    warn(NOT_CONFIGURED);
    return [];
  }
  const result = await collect(cfg);
  result.warnings.forEach(warn);
  return apply(result.values, env, cfg);
}

/**
 * Load into process.env synchronously, for `node -r` and the first line of a
 * CommonJS entry file. The HTTP work runs in a child Node process; the values
 * come back over a pipe, never through argv or disk.
 */
function loadSync(options) {
  const env = (options && options.env) || process.env;
  if (env[LOADED_MARK]) return [];
  const cfg = readConfig(options, env);
  if (!cfg.configured) {
    warn(NOT_CONFIGURED);
    return [];
  }
  const childEnv = Object.assign({}, process.env, env);
  // Without this the child would preload us again (NODE_OPTIONS=-r ...) and recurse.
  delete childEnv.NODE_OPTIONS;
  childEnv[LOADED_MARK] = '1';
  childEnv.VAULT_ENV_INTERNAL_OPTIONS = JSON.stringify(serializableOptions(options, cfg));
  const out = childProcess.spawnSync(process.execPath, [__filename, '--internal-fetch'], {
    env: childEnv,
    stdio: ['ignore', 'pipe', 'inherit'],
    maxBuffer: 64 * 1024 * 1024,
    windowsHide: true,
  });
  if (out.error) throw new VaultEnvError(`Could not start the fetch process: ${out.error.code || out.error.message}.`, 'unavailable');
  let msg;
  try {
    msg = JSON.parse(out.stdout.toString('utf8'));
  } catch (e) {
    throw new VaultEnvError(`The fetch process exited with status ${out.status} and no result.`, 'unavailable');
  }
  if (!msg.ok) throw new VaultEnvError(msg.error.message, msg.error.code);
  return apply(msg.values, env, cfg);
}

function serializableOptions(options, cfg) {
  const o = {};
  for (const k of ['addr', 'imports', 'base', 'tokenFile', 'namespace', 'cacert', 'capath', 'timeout', 'retries', 'retryDelayMs', 'caseInsensitive', 'allowHttp']) {
    if (options && options[k] !== undefined) o[k] = options[k];
  }
  // The token travels in the child's environment, never in argv.
  o.token = cfg.token;
  return o;
}

async function internalFetch() {
  const options = JSON.parse(process.env.VAULT_ENV_INTERNAL_OPTIONS || '{}');
  const env = Object.assign({}, process.env);
  delete env.VAULT_ENV_INTERNAL_OPTIONS;
  try {
    const cfg = readConfig(options, env);
    const result = await collect(cfg);
    result.warnings.forEach(warn);
    process.stdout.write(JSON.stringify({ ok: true, values: result.values }));
  } catch (e) {
    const err = e instanceof VaultEnvError ? e : new VaultEnvError(`Unexpected error: ${e && e.message}`, 'error');
    process.stdout.write(JSON.stringify({ ok: false, error: { message: err.message, code: err.code } }));
  }
}

// ---------------------------------------------------------------------------
// CLI

const HELP = `vault-env-loader ${VERSION} — load Vault KV secrets into environment variables, then run a command.

Usage:
  vault-env-loader [options] -- <command> [args...]
  vault-env-loader check [options]      show what would be loaded (names only, never values)
  vault-env-loader --version

Options (each also has an environment variable):
  --addr <url>          VAULT_ADDR
  --token-file <path>   VAULT_TOKEN_FILE        (the token itself only via VAULT_TOKEN)
  --import <spec>       VAULT_ENV_IMPORT        repeatable; comma-separated in the variable
  --base <path>         VAULT_ENV_BASE          base for relative imports
  --override            VAULT_ENV_OVERRIDE      replace variables that are already set
  --keep-token          VAULT_ENV_KEEP_TOKEN    pass VAULT_TOKEN on to the command
  --timeout <seconds>   VAULT_ENV_TIMEOUT       per request, default 10
  --retries <n>         VAULT_ENV_RETRIES       default 3

Import spec:  [optional:]vault://<mount>/<path> | <relative path> | vault://   [?prefix=X_&name=auto|verbatim|upper&kv=1|2]
Docs: https://github.com/kaylovh/vault-env-loader
`;

function parseArgs(argv) {
  const opts = {};
  const imports = [];
  let command = null;
  let sub = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => {
      if (i + 1 >= argv.length) throw new VaultEnvError(`${a} needs a value.`, 'config');
      return argv[++i];
    };
    if (a === '--') {
      command = argv.slice(i + 1);
      break;
    } else if (a === '--addr') opts.addr = val();
    else if (a === '--token-file') opts.tokenFile = val();
    else if (a === '--import') imports.push(...splitList(val()));
    else if (a === '--base') opts.base = val();
    else if (a === '--override') opts.override = true;
    else if (a === '--keep-token') opts.keepToken = true;
    else if (a === '--timeout') opts.timeout = val();
    else if (a === '--retries') opts.retries = val();
    else if (a === '--token') throw new VaultEnvError('There is no --token option: command-line arguments are visible to every user (ps). Use VAULT_TOKEN or --token-file.', 'config');
    else if (a === 'check' && sub === null) sub = 'check';
    else if (a === '--version' || a === '-v') sub = 'version';
    else if (a === '--help' || a === '-h') sub = 'help';
    else if (!a.startsWith('-') && sub === null) {
      // Allow "vault-env-loader node app.js" without "--".
      command = argv.slice(i);
      break;
    } else throw new VaultEnvError(`Unknown option ${a}. See --help.`, 'config');
  }
  if (imports.length) opts.imports = imports;
  return { opts, command, sub };
}

async function check(opts) {
  const cfg = readConfig(opts, process.env);
  if (!cfg.configured) {
    process.stdout.write(`${NOT_CONFIGURED}\n`);
    return 0;
  }
  const result = await collect(cfg);
  const r = report(result);
  const lines = [];
  lines.push(`vault-env-loader ${VERSION}`);
  lines.push(`addr     ${cfg.addr}`);
  if (r.token) {
    const meta = Object.keys(r.token.meta).map((k) => `${k}=${r.token.meta[k]}`).join(' ');
    lines.push(`token    ${r.token.ttl ? `expires in ${Math.round(r.token.ttl / 3600)}h` : 'no expiry'}${meta ? `, ${meta}` : ''}`);
  } else lines.push('token    (lookup-self not permitted)');
  lines.push(`base     ${r.base ? `${r.base} (from ${r.baseSource})` : '(none)'}`);
  const { kept } = plan(result.values, process.env, cfg.override);
  const canon = (n) => (cfg.caseInsensitive ? n.toUpperCase() : n);
  const lastImport = new Map();
  r.imports.forEach((imp, i) => imp.variables.forEach((v) => lastImport.set(canon(v.name), i)));
  r.imports.forEach((imp, i) => {
    lines.push('');
    lines.push(`import   ${imp.import}  ->  ${imp.path}  (kv v${imp.kv}${imp.version !== undefined ? `, version ${imp.version}` : ''})${imp.skipped ? '  [optional, not found: skipped]' : ''}`);
    const width = Math.max(0, ...imp.variables.map((v) => v.name.length));
    for (const v of imp.variables) {
      const notes = [];
      if (v.name !== v.key) notes.push(`from ${v.key}`);
      if (lastImport.get(canon(v.name)) !== i) notes.push('overridden by a later import');
      else if (kept.includes(v.name)) notes.push('already set: kept');
      lines.push(`  ${v.name.padEnd(width)}  ${String(v.length).padStart(5)} chars${notes.length ? `  (${notes.join('; ')})` : ''}`);
    }
  });
  result.warnings.forEach(warn);
  process.stdout.write(`${lines.join('\n')}\n`);
  return 0;
}

function run(opts, command) {
  let env = Object.assign({}, process.env);
  const go = () => exec(command, env);
  if (env[LOADED_MARK]) return Promise.resolve(go());
  const cfg = readConfig(opts, env);
  if (!cfg.configured) {
    warn(NOT_CONFIGURED);
    return Promise.resolve(go());
  }
  return collect(cfg).then((result) => {
    result.warnings.forEach(warn);
    apply(result.values, env, cfg);
    return go();
  });
}

function exec(command, env) {
  return new Promise((resolve) => {
    const child = childProcess.spawn(command[0], command.slice(1), { stdio: 'inherit', env, windowsHide: false });
    const forward = (sig) => () => {
      try {
        child.kill(sig);
      } catch (e) {
        /* already gone */
      }
    };
    const signals = ['SIGINT', 'SIGTERM', 'SIGHUP'].filter((s) => !(process.platform === 'win32' && s === 'SIGHUP'));
    const handlers = signals.map((s) => [s, forward(s)]);
    handlers.forEach(([s, h]) => process.on(s, h));
    child.on('error', (e) => {
      handlers.forEach(([s, h]) => process.removeListener(s, h));
      warn(e.code === 'ENOENT' ? `Command not found: ${command[0]}` : `Could not start ${command[0]}: ${e.code || e.message}`);
      resolve(e.code === 'ENOENT' ? 127 : 126);
    });
    child.on('exit', (code, signal) => {
      handlers.forEach(([s, h]) => process.removeListener(s, h));
      if (signal) resolve(128 + (os.constants.signals[signal] || 0));
      else resolve(code === null ? 1 : code);
    });
  });
}

async function main(argv) {
  if (argv[0] === '--internal-fetch') return internalFetch().then(() => 0);
  let parsed;
  try {
    parsed = parseArgs(argv);
    if (parsed.sub === 'version') {
      process.stdout.write(`${VERSION}\n`);
      return 0;
    }
    if (parsed.sub === 'help' || (!parsed.sub && !parsed.command)) {
      process.stdout.write(HELP);
      return parsed.sub === 'help' ? 0 : 2;
    }
    if (parsed.sub === 'check') return await check(parsed.opts);
    if (!parsed.command || !parsed.command.length) throw new VaultEnvError('No command given after --.', 'config');
    return await run(parsed.opts, parsed.command);
  } catch (e) {
    if (e instanceof VaultEnvError) {
      warn(e.message);
      return EX_CONFIG;
    }
    warn(`Unexpected error: ${(e && e.message) || e}`);
    return EX_CONFIG;
  }
}

module.exports = {
  load,
  loadSync,
  fetch: fetchValues,
  VaultEnvError,
  VERSION,
  // Exposed for tests; not part of the public API.
  _internal: { readConfig, parseImport, envName, mapEntries, mergeImports, plan, aliasFailures, retryable, parseArgs, main },
};

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}

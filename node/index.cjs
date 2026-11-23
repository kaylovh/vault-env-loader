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
const crypto = require('crypto');

const VERSION = '0.4.0';
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
const APPROLE_MOUNT = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;
const TRUTHY = ['1', 'true', 'yes', 'on'];
const FALSY = ['0', 'false', 'no', 'off'];
const ASSERTION_LIFETIME = 120;
const CERT_WARN_DAYS = 30;

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
  return typeof v === 'string' && TRUTHY.includes(v.trim().toLowerCase());
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
  if (skip !== undefined && !FALSY.includes(skip.toLowerCase())) {
    throw new VaultEnvError('VAULT_SKIP_VERIFY is set, but vault-env-loader never skips TLS verification. Unset it and point VAULT_CACERT at your CA instead.', 'config');
  }
  const enabled = enabledSwitch(env);

  const addr = nonEmpty(pick('addr', 'VAULT_ADDR'));
  let imports = pick('imports', 'VAULT_ENV_IMPORT');
  if (typeof imports === 'string') imports = splitList(imports);
  imports = (imports || []).map((s) => String(s).trim()).filter(Boolean);

  const tokenFile = nonEmpty(pick('tokenFile', 'VAULT_TOKEN_FILE'));
  let token = options.token !== undefined ? options.token : nonEmpty(env.VAULT_TOKEN);
  const roleIdFile = nonEmpty(pick('roleIdFile', 'VAULT_ROLE_ID_FILE'));
  let roleId = options.roleId !== undefined ? nonEmpty(options.roleId) : nonEmpty(env.VAULT_ROLE_ID);
  const secretIdFile = nonEmpty(pick('secretIdFile', 'VAULT_SECRET_ID_FILE'));
  let secretId = options.secretId !== undefined ? nonEmpty(options.secretId) : nonEmpty(env.VAULT_SECRET_ID);
  const appRoleGiven = Boolean(roleId || roleIdFile || secretId || secretIdFile);
  // Certificate login: only VAULT_CLIENT_CERTIFICATE_PATH selects it. A key path or
  // password without it changes nothing, as in 0.3. The password is taken as it is.
  const certPath = nonEmpty(pick('clientCertificatePath', 'VAULT_CLIENT_CERTIFICATE_PATH'));
  const keyPath = certPath ? nonEmpty(pick('clientKeyPath', 'VAULT_CLIENT_KEY_PATH')) : undefined;
  const passwordGiven = options.clientCertificatePassword !== undefined && options.clientCertificatePassword !== null;
  let password = passwordGiven ? String(options.clientCertificatePassword) : env.VAULT_CLIENT_CERTIFICATE_PASSWORD;
  if (password === '') password = undefined;
  const passwordFile = nonEmpty(pick('clientCertificatePasswordFile', 'VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE'));

  // A token, when there is one, is used exactly as before AppRole support; AppRole
  // variables beside it are left alone (they may be meant for another tool).
  // Decided from what is set, before any file is read, so that a disabled run
  // removes the same variables a load would.
  const auth = token || tokenFile ? 'token' : certPath && (roleId || roleIdFile) && !(secretId || secretIdFile) ? 'certificate' : 'approle';
  const used = [];
  if (auth !== 'token') {
    if (roleId) {
      if (options.roleId === undefined) used.push('VAULT_ROLE_ID');
    } else if (roleIdFile && options.roleIdFile === undefined) used.push('VAULT_ROLE_ID_FILE');
    if (secretId) {
      if (options.secretId === undefined) used.push('VAULT_SECRET_ID');
    } else if (secretIdFile && options.secretIdFile === undefined) used.push('VAULT_SECRET_ID_FILE');
    if (certPath) {
      if (options.clientCertificatePath === undefined) used.push('VAULT_CLIENT_CERTIFICATE_PATH');
      if (keyPath && options.clientKeyPath === undefined) used.push('VAULT_CLIENT_KEY_PATH');
      if (password !== undefined) {
        if (!passwordGiven) used.push('VAULT_CLIENT_CERTIFICATE_PASSWORD');
      } else if (passwordFile && options.clientCertificatePasswordFile === undefined) used.push('VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE');
    }
  }
  const tokenFromFile = auth === 'token' && !nonEmpty(env.VAULT_TOKEN) && options.token === undefined && Boolean(tokenFile);
  const keepToken = options.keepToken !== undefined ? Boolean(options.keepToken) : truthy(env.VAULT_ENV_KEEP_TOKEN);
  if (enabled === false) return { configured: false, disabled: true, keepToken, tokenFromFile, appRoleVarsUsed: used };

  const configured = Boolean(addr || imports.length);
  if (!configured) {
    if (enabled) throw new VaultEnvError(ENABLED_NOT_CONFIGURED, 'config');
    return { configured: false };
  }

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
  const notes = [];
  if (auth === 'token') {
    if (certPath) notes.push('VAULT_TOKEN is set, so VAULT_ROLE_ID / VAULT_SECRET_ID / VAULT_CLIENT_CERTIFICATE_PATH are ignored.');
    else if (appRoleGiven) notes.push('VAULT_TOKEN is set, so VAULT_ROLE_ID / VAULT_SECRET_ID are ignored.');
  } else if (roleId || roleIdFile) {
    if (certPath && auth !== 'certificate') {
      throw new VaultEnvError('Both a secret ID and a client certificate are set (VAULT_SECRET_ID / VAULT_CLIENT_CERTIFICATE_PATH): AppRole login takes one or the other.', 'config');
    }
    if (!roleId) roleId = readSecretFile(roleIdFile, 'VAULT_ROLE_ID_FILE');
    if (auth === 'certificate') {
      if (password === undefined && passwordFile) password = readPasswordFile(passwordFile);
    } else if (!secretId && secretIdFile) secretId = readSecretFile(secretIdFile, 'VAULT_SECRET_ID_FILE');
  } else if (certPath) {
    throw new VaultEnvError('VAULT_CLIENT_CERTIFICATE_PATH is set but VAULT_ROLE_ID is not: certificate login needs both.', 'config');
  } else if (appRoleGiven) {
    throw new VaultEnvError('VAULT_SECRET_ID is set but VAULT_ROLE_ID is not: AppRole login needs both.', 'config');
  } else {
    throw new VaultEnvError('No token: set VAULT_TOKEN or VAULT_TOKEN_FILE.', 'config');
  }
  const approleMount = nonEmpty(pick('approleMount', 'VAULT_ENV_APPROLE_MOUNT')) || 'approle';
  if (!validMount(approleMount)) throw new VaultEnvError('VAULT_ENV_APPROLE_MOUNT must be a mount path such as approle.', 'config');
  const jwtMount = auth === 'certificate' ? nonEmpty(pick('jwtMount', 'VAULT_ENV_JWT_MOUNT')) || 'jwt' : undefined;
  if (jwtMount !== undefined && !validMount(jwtMount)) throw new VaultEnvError('VAULT_ENV_JWT_MOUNT must be a mount path such as jwt.', 'config');

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
    auth,
    token: auth === 'token' ? token : null,
    roleId: auth !== 'token' ? roleId : undefined,
    secretId: auth === 'approle' ? secretId : undefined,
    approleMount,
    certificatePath: auth === 'certificate' ? certPath : undefined,
    keyPath: auth === 'certificate' ? keyPath : undefined,
    password: auth === 'certificate' ? password : undefined,
    jwtMount,
    rawAddr: addr,
    appRoleVarsUsed: used,
    notes,
    tokenFromFile,
    namespace: nonEmpty(pick('namespace', 'VAULT_NAMESPACE')),
    ca: loadCa(nonEmpty(pick('cacert', 'VAULT_CACERT')), nonEmpty(pick('capath', 'VAULT_CAPATH'))),
    imports: imports.map(parseImport),
    base: nonEmpty(pick('base', 'VAULT_ENV_BASE')),
    override: options.override !== undefined ? Boolean(options.override) : truthy(env.VAULT_ENV_OVERRIDE),
    keepToken,
    timeoutMs: num(pick('timeout', 'VAULT_ENV_TIMEOUT'), 10, 'VAULT_ENV_TIMEOUT') * 1000,
    retries: Math.floor(num(pick('retries', 'VAULT_ENV_RETRIES'), 3, 'VAULT_ENV_RETRIES')),
    retryDelayMs: options.retryDelayMs !== undefined ? options.retryDelayMs : 1000,
    caseInsensitive: options.caseInsensitive !== undefined ? Boolean(options.caseInsensitive) : process.platform === 'win32',
  };
}

// VAULT_ENV_ENABLED: undefined when unset or blank (0.2 behaviour), false to load
// nothing, true to require a configuration. Anything else is a mistake, not a guess.
function enabledSwitch(env) {
  const v = nonEmpty(env.VAULT_ENV_ENABLED);
  if (v === undefined) return undefined;
  if (FALSY.includes(v.toLowerCase())) return false;
  if (TRUTHY.includes(v.toLowerCase())) return true;
  throw new VaultEnvError('VAULT_ENV_ENABLED must be true or false (or 1/0, yes/no, on/off).', 'config');
}

function readSecretFile(file, name) {
  let v;
  try {
    v = fs.readFileSync(file, 'utf8').trim();
  } catch (e) {
    throw new VaultEnvError(`Cannot read ${name} (${file}): ${e.code || 'error'}.`, 'config');
  }
  if (!v) throw new VaultEnvError(`${name} (${file}) is empty.`, 'config');
  return v;
}

// A password file loses one trailing line break, nothing else: a password may
// begin or end with spaces.
function readPasswordFile(file) {
  let v;
  try {
    v = fs.readFileSync(file, 'utf8').replace(/\r?\n$/, '');
  } catch (e) {
    throw new VaultEnvError(`Cannot read VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE (${file}): ${e.code || 'error'}.`, 'config');
  }
  if (!v) throw new VaultEnvError(`VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE (${file}) is empty.`, 'config');
  return v;
}

function validMount(m) {
  return APPROLE_MOUNT.test(m) && !m.split('/').some((seg) => seg === '.' || seg === '..');
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
  return httpRequest(cfg, 'GET', apiPath);
}

// One request. `body` is sent as JSON; the login request carries no token.
// A rejection says whether the connection was ever established (`connected`),
// so a login is only retried when the server cannot have seen it.
function httpRequest(cfg, method, apiPath, body, opts) {
  const url = new URL(`${cfg.addr}/v1/${apiPath}`);
  const lib = url.protocol === 'https:' ? https : http;
  const headers = {};
  if (!(opts && opts.noToken)) headers['X-Vault-Token'] = cfg.token;
  Object.assign(headers, {
    'X-Vault-Request': 'true',
    'User-Agent': `vault-env-loader/${VERSION} node/${process.versions.node}`,
    Accept: 'application/json',
  });
  if (cfg.namespace) headers['X-Vault-Namespace'] = cfg.namespace;
  const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), 'utf8');
  if (payload) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = String(payload.length);
  }
  let connected = false;
  return new Promise((resolve, reject) => {
    const fail = (e) => reject(Object.assign(e, { connected }));
    const req = lib.request(url, { method, headers, ca: cfg.ca, agent: false }, (res) => {
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
      res.on('error', fail);
    });
    req.on('socket', (sock) => {
      if (!sock.connecting) connected = true;
      else sock.once('connect', () => (connected = true));
    });
    req.setTimeout(cfg.timeoutMs, () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    req.on('error', fail);
    req.end(payload);
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
// AppRole: log in once, read, revoke the session.

// Retry a login only when Vault cannot have processed it: the connection never
// came up, or Vault said so (429, 503). After the request went out, a retry
// could spend another use of a limited secret ID and then fail as "invalid".
async function appRoleLogin(cfg) {
  const body = { role_id: cfg.roleId };
  if (cfg.secretId) body.secret_id = cfg.secretId;
  const apiPath = `auth/${cfg.approleMount}/login`;
  let attempt = 0;
  let res;
  for (;;) {
    let netErr;
    res = undefined;
    try {
      res = await httpRequest(cfg, 'POST', apiPath, body, { noToken: true });
    } catch (e) {
      netErr = e;
    }
    const again = res ? [429, 503].includes(res.status) : !netErr.connected;
    if (!again || attempt >= cfg.retries) {
      if (netErr) {
        const what = netErr.code === 'ETIMEDOUT' ? 'timed out' : `failed (${netErr.code || 'network error'})`;
        throw new VaultEnvError(`AppRole login to Vault ${what}.`, 'unavailable');
      }
      break;
    }
    await sleep(cfg.retryDelayMs * Math.pow(2, attempt));
    attempt += 1;
  }
  if (res.status === 400 || res.status === 401 || res.status === 403) {
    throw new VaultEnvError(`AppRole login failed: the role ID or secret ID is invalid, expired or used up (mount ${cfg.approleMount}).`, 'auth');
  }
  if (res.status !== 200) throw new VaultEnvError(`Vault answered HTTP ${res.status} to the AppRole login.`, 'unavailable');
  const token = res.body && res.body.auth && res.body.auth.client_token;
  if (typeof token !== 'string' || !token) throw new VaultEnvError('Vault answered the AppRole login without a token (unexpected response).', 'unavailable');
  cfg.token = token;
}

// Best effort: the session expires by itself if this fails.
async function revokeSession(cfg) {
  const what = cfg.auth === 'certificate' ? 'certificate login session' : 'AppRole session';
  try {
    const res = await httpRequest(cfg, 'POST', 'auth/token/revoke-self');
    if (res.status !== 204 && res.status !== 200) warn(`Could not revoke the ${what} (HTTP ${res.status}); it expires by itself.`);
  } catch (e) {
    warn(`Could not revoke the ${what} (${e.code || 'network error'}); it expires by itself.`);
  } finally {
    cfg.token = null;
  }
}

// ---------------------------------------------------------------------------
// Certificate login: sign a short-lived JWT (a client assertion) with the private
// key, log in with auth/<mount>/login {role, jwt}, read, revoke the session.
// One code path on every Node version: no X509Certificate, no 'base64url' and no
// asymmetricKeyDetails, none of which Node 14 has; the certificate's validity and
// public key come from a small DER walk.

const PEM_CERT = /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----/;
const PEM_KEY = /-----BEGIN ((?:RSA |EC |ENCRYPTED )?PRIVATE KEY)-----[\s\S]+?-----END \1-----/;
// DER of the named-curve OIDs inside a SubjectPublicKeyInfo.
const CURVES = [
  { alg: 'ES256', hash: 'sha256', size: 32, oid: Buffer.from('06082a8648ce3d030107', 'hex') },
  { alg: 'ES384', hash: 'sha384', size: 48, oid: Buffer.from('06052b81040022', 'hex') },
];

function b64url(buf) {
  return buf.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// One DER TLV at `pos`: { tag, start (of the value), end }.
function derItem(buf, pos) {
  if (pos + 2 > buf.length) throw new Error('truncated');
  const tag = buf[pos];
  let len = buf[pos + 1];
  let start = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4 || start + n > buf.length) throw new Error('bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i];
    start += n;
  }
  if (start + len > buf.length) throw new Error('truncated');
  return { tag, pos, start, end: start + len };
}

function derChildren(buf, item) {
  const out = [];
  for (let pos = item.start; pos < item.end; ) {
    const c = derItem(buf, pos);
    out.push(c);
    pos = c.end;
  }
  return out;
}

function derTime(buf, item) {
  const s = buf.slice(item.start, item.end).toString('latin1');
  let m;
  if (item.tag === 0x17 && (m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s))) {
    const yy = Number(m[1]);
    return Date.UTC(yy < 50 ? 2000 + yy : 1900 + yy, m[2] - 1, m[3], m[4], m[5], m[6]) / 1000;
  }
  if (item.tag === 0x18 && (m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(s))) {
    return Date.UTC(Number(m[1]), m[2] - 1, m[3], m[4], m[5], m[6]) / 1000;
  }
  throw new Error('bad time');
}

// Certificate DER -> { notAfter (epoch seconds), spki (DER) }.
function parseCertificateDer(der) {
  const cert = derItem(der, 0);
  const tbs = derChildren(der, cert)[0];
  const f = derChildren(der, tbs);
  const i = f[0].tag === 0xa0 ? 1 : 0; // [0] version is optional
  const validity = derChildren(der, f[i + 3]);
  const spki = f[i + 5];
  if (validity.length !== 2 || spki.tag !== 0x30) throw new Error('bad certificate');
  return { notAfter: derTime(der, validity[1]), spki: der.slice(spki.pos, spki.end) };
}

/**
 * Read the certificate and its private key. Every problem is a config error,
 * raised before any request; messages name files, never their contents.
 */
function loadClientCertificate(certPath, keyPath, password) {
  const read = (file, what) => {
    try {
      return fs.readFileSync(file, 'latin1');
    } catch (e) {
      throw new VaultEnvError(`Cannot read the client ${what} file (${file}): ${e.code || 'error'}.`, 'config');
    }
  };
  const certText = read(certPath, 'certificate');
  const cm = PEM_CERT.exec(certText);
  if (!cm) {
    throw new VaultEnvError(`The client certificate file (${certPath}) holds no PEM certificate (-----BEGIN CERTIFICATE-----). PKCS#12 / PFX is not supported: convert it to PEM.`, 'config');
  }
  const der = Buffer.from(cm[1].replace(/\s+/g, ''), 'base64');
  let parsed;
  let certKey;
  try {
    parsed = parseCertificateDer(der);
    certKey = crypto.createPublicKey({ key: parsed.spki, format: 'der', type: 'spki' });
  } catch (e) {
    throw new VaultEnvError(`The client certificate file (${certPath}) does not hold a valid X.509 certificate.`, 'config');
  }
  const keyFile = keyPath || certPath;
  const keyText = keyPath ? read(keyPath, 'key') : certText;
  const km = PEM_KEY.exec(keyText);
  if (!km) {
    throw new VaultEnvError(keyPath ? `No private key in the client key file (${keyPath}).` : `No private key in the client certificate file (${certPath}): put the key in the same PEM file, or set VAULT_CLIENT_KEY_PATH.`, 'config');
  }
  const encrypted = km[1] === 'ENCRYPTED PRIVATE KEY' || /Proc-Type:\s*4,ENCRYPTED/.test(km[0]);
  if (encrypted && password === undefined) {
    throw new VaultEnvError(`The private key in ${keyFile} is encrypted: set VAULT_CLIENT_CERTIFICATE_PASSWORD or VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE.`, 'config');
  }
  let key;
  try {
    key = crypto.createPrivateKey(encrypted ? { key: km[0], format: 'pem', passphrase: password } : { key: km[0], format: 'pem' });
  } catch (e) {
    throw new VaultEnvError(encrypted ? `Cannot decrypt the private key in ${keyFile}: wrong password.` : `The private key in ${keyFile} is not a valid PEM key.`, 'config');
  }
  const spki = crypto.createPublicKey(key).export({ type: 'spki', format: 'der' });
  let alg;
  let curve;
  if (key.asymmetricKeyType === 'rsa') alg = 'RS256';
  else if (key.asymmetricKeyType === 'ec') {
    curve = CURVES.find((c) => spki.indexOf(c.oid) >= 0);
    if (curve) alg = curve.alg;
  }
  if (!alg) throw new VaultEnvError(`Unsupported key in ${keyFile}: use RSA or EC P-256 / P-384.`, 'config');
  if (!spki.equals(certKey.export({ type: 'spki', format: 'der' }))) {
    throw new VaultEnvError(`The private key in ${keyFile} does not belong to the certificate in ${certPath}.`, 'config');
  }
  return { key, alg, curve, x5t: b64url(crypto.createHash('sha256').update(der).digest()), notAfter: parsed.notAfter };
}

/** VAULT_ADDR normalised + /v1/auth/<mount>/login: the aud claim. */
function audience(addr, mount) {
  let url;
  try {
    url = new URL(String(addr).trim());
  } catch (e) {
    throw new VaultEnvError('VAULT_ADDR is not a valid URL.', 'config');
  }
  return `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, '')}/v1/auth/${mount}/login`;
}

// Header, claims and signature. A new iat and jti on every call.
function signAssertion(cred, roleId, aud, nowSec) {
  const iat = Math.floor(nowSec === undefined ? Date.now() / 1000 : nowSec);
  const header = { alg: cred.alg, typ: 'JWT', 'x5t#S256': cred.x5t };
  const claims = { iss: roleId, sub: roleId, aud, iat, exp: iat + ASSERTION_LIFETIME, jti: crypto.randomBytes(16).toString('hex') };
  const input = `${b64url(Buffer.from(JSON.stringify(header), 'utf8'))}.${b64url(Buffer.from(JSON.stringify(claims), 'utf8'))}`;
  const data = Buffer.from(input, 'ascii');
  const sig = cred.curve ? crypto.sign(cred.curve.hash, data, { key: cred.key, dsaEncoding: 'ieee-p1363' }) : crypto.sign('sha256', data, cred.key);
  return `${input}.${b64url(sig)}`;
}

function isoDate(sec) {
  return new Date(sec * 1000).toISOString().slice(0, 10);
}

// Days left (rounded down), the warning (below 30 days, or expired) and check's text.
function certificateStatus(notAfter, nowSec) {
  const days = Math.floor((notAfter - nowSec) / 86400);
  const date = isoDate(notAfter);
  const expired = notAfter <= nowSec;
  let warning = null;
  if (expired) warning = `The client certificate expired on ${date}.`;
  else if (days < CERT_WARN_DAYS) warning = `The client certificate expires in ${days} day(s), on ${date}. Replace it before then.`;
  return { days, warning, text: expired ? `expired ${date}` : `expires ${date}, ${days} days` };
}

function certificateCheckLine(roleId, x5t, status, mount) {
  return `auth     certificate (role_id ${String(roleId).slice(0, 8)}..., cert ${x5t.slice(0, 8)}..., ${status.text}, mount ${mount}; session revoked after reading)`;
}

/**
 * A client assertion for auth/<mount>/login, for Vault clients that cannot sign
 * one themselves (node-vault: vault.jwtLogin({ role, jwt })). Synchronous.
 */
function clientAssertion(o) {
  o = o || {};
  for (const k of ['roleId', 'certificatePath', 'vaultAddr']) {
    if (!nonEmpty(o[k])) throw new VaultEnvError(`clientAssertion() needs ${k}.`, 'config');
  }
  const mount = nonEmpty(o.mount) || 'jwt';
  if (!validMount(mount)) throw new VaultEnvError('The JWT mount must be a mount path such as jwt.', 'config');
  const password = o.password === undefined || o.password === null || o.password === '' ? undefined : String(o.password);
  const cred = loadClientCertificate(o.certificatePath.trim(), nonEmpty(o.keyPath), password);
  return signAssertion(cred, o.roleId.trim(), audience(o.vaultAddr, mount));
}

// Unlike a secret ID, a certificate can log in any number of times, so every
// failure that may pass is retried (connection, timeout, 429, 5xx), each time
// with a new assertion. A session the server may have issued expires by itself.
async function certificateLogin(cfg) {
  const apiPath = `auth/${cfg.jwtMount}/login`;
  const aud = audience(cfg.rawAddr, cfg.jwtMount);
  let attempt = 0;
  let res;
  for (;;) {
    let netErr;
    res = undefined;
    try {
      res = await httpRequest(cfg, 'POST', apiPath, { role: cfg.roleId, jwt: signAssertion(cfg.credential, cfg.roleId, aud) }, { noToken: true });
    } catch (e) {
      netErr = e;
    }
    const again = res ? res.status === 429 || res.status >= 500 : true;
    if (!again || attempt >= cfg.retries) {
      if (netErr) {
        const what = netErr.code === 'ETIMEDOUT' ? 'timed out' : `failed (${netErr.code || 'network error'})`;
        throw new VaultEnvError(`Certificate login to Vault ${what}.`, 'unavailable');
      }
      break;
    }
    await sleep(cfg.retryDelayMs * Math.pow(2, attempt));
    attempt += 1;
  }
  if (res.status === 400 || res.status === 401 || res.status === 403) {
    throw new VaultEnvError(`Certificate login failed: the role ID or certificate is not accepted (mount ${cfg.jwtMount}).`, 'auth');
  }
  if (res.status !== 200) throw new VaultEnvError(`Vault answered HTTP ${res.status} to the certificate login.`, 'unavailable');
  const token = res.body && res.body.auth && res.body.auth.client_token;
  if (typeof token !== 'string' || !token) throw new VaultEnvError('Vault answered the certificate login without a token (unexpected response).', 'unavailable');
  cfg.token = token;
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
  if (cfg.auth === 'token') return collectWith(cfg);
  if (cfg.auth === 'certificate') {
    // Read and check the files first: a bad certificate fails before any request.
    cfg.credential = loadClientCertificate(cfg.certificatePath, cfg.keyPath, cfg.password);
    cfg.certificate = certificateStatus(cfg.credential.notAfter, Date.now() / 1000);
    await certificateLogin(cfg);
  } else await appRoleLogin(cfg);
  try {
    return await collectWith(cfg);
  } finally {
    await revokeSession(cfg);
  }
}

async function collectWith(cfg) {
  const warnings = (cfg.notes || []).slice();
  if (cfg.insecureHttp) warnings.push('VAULT_ADDR uses plain http: the token and every secret cross the network unencrypted.');
  if (cfg.certificate && cfg.certificate.warning) warnings.push(cfg.certificate.warning);
  const self = await lookupSelf(cfg);
  // An AppRole session is short-lived by design: its TTL is no reason to warn.
  if (cfg.auth === 'token' && self && !self.denied && self.ttl > 0 && self.ttl < TTL_WARN_SECONDS) {
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
  stripCredentials(env, cfg);
  return Object.keys(set);
}

// After a load, and when VAULT_ENV_ENABLED is off: the application never sees the credentials.
function stripCredentials(env, cfg) {
  if (cfg.keepToken) return;
  delete env.VAULT_TOKEN;
  if (cfg.tokenFromFile) delete env.VAULT_TOKEN_FILE;
  // Only the AppRole variables this run actually used.
  for (const name of cfg.appRoleVarsUsed || []) delete env[name];
}

const NOT_CONFIGURED = 'VAULT_ADDR and VAULT_ENV_IMPORT are not set; nothing loaded from Vault.';
const DISABLED = 'VAULT_ENV_ENABLED is off; nothing loaded from Vault.';
const ENABLED_NOT_CONFIGURED = 'VAULT_ENV_ENABLED is on, but VAULT_ADDR and VAULT_ENV_IMPORT are not set.';

// Nothing to load. Switched off, the credentials still leave the environment;
// VAULT_ENV_LOADED is not set, since nothing was loaded.
function notLoaded(env, cfg) {
  if (cfg.disabled) {
    warn(DISABLED);
    stripCredentials(env, cfg);
  } else warn(NOT_CONFIGURED);
  return [];
}

// ---------------------------------------------------------------------------
// Library API

/** Read the configured imports and return { NAME: value } without touching process.env. */
async function fetchValues(options) {
  const cfg = readConfig(options, (options && options.env) || process.env);
  if (cfg.disabled) {
    warn(DISABLED);
    return {};
  }
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
  if (!cfg.configured) return notLoaded(env, cfg);
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
  if (!cfg.configured) return notLoaded(env, cfg);
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
  for (const k of ['addr', 'imports', 'base', 'tokenFile', 'namespace', 'cacert', 'capath', 'timeout', 'retries', 'retryDelayMs', 'caseInsensitive', 'allowHttp', 'approleMount', 'jwtMount']) {
    if (options && options[k] !== undefined) o[k] = options[k];
  }
  // Credentials travel in the child's environment, never in argv. With AppRole
  // the child logs in and revokes; the session token never comes back.
  if (cfg.auth === 'approle') {
    o.roleId = cfg.roleId;
    if (cfg.secretId) o.secretId = cfg.secretId;
  } else if (cfg.auth === 'certificate') {
    o.roleId = cfg.roleId;
    o.clientCertificatePath = cfg.certificatePath;
    if (cfg.keyPath) o.clientKeyPath = cfg.keyPath;
    if (cfg.password !== undefined) o.clientCertificatePassword = cfg.password;
  } else o.token = cfg.token;
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
  --role-id-file <path> VAULT_ROLE_ID_FILE      AppRole, when no token is set (or VAULT_ROLE_ID)
  --secret-id-file <path> VAULT_SECRET_ID_FILE  (the secret ID itself only via VAULT_SECRET_ID)
  --approle-mount <path> VAULT_ENV_APPROLE_MOUNT default approle
  --client-certificate-path <path>
                        VAULT_CLIENT_CERTIFICATE_PATH  certificate login with the role ID (one PEM file: key and certificate)
  --client-key-path <path>
                        VAULT_CLIENT_KEY_PATH   the key, when it is in a file of its own
  --jwt-mount <path>    VAULT_ENV_JWT_MOUNT     default jwt
  --import <spec>       VAULT_ENV_IMPORT        repeatable; comma-separated in the variable
  --base <path>         VAULT_ENV_BASE          base for relative imports
  --override            VAULT_ENV_OVERRIDE      replace variables that are already set
  --keep-token          VAULT_ENV_KEEP_TOKEN    pass VAULT_TOKEN (or the AppRole / certificate variables) on to the command
  --timeout <seconds>   VAULT_ENV_TIMEOUT       per request, default 10
  --retries <n>         VAULT_ENV_RETRIES       default 3

Environment only:
  VAULT_ENV_ENABLED     false: load nothing, remove the credentials, run the command
                        true: fail unless VAULT_ADDR and VAULT_ENV_IMPORT are set
  VAULT_CLIENT_CERTIFICATE_PASSWORD / VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE
                        the password of an encrypted private key

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
    else if (a === '--role-id-file') opts.roleIdFile = val();
    else if (a === '--secret-id-file') opts.secretIdFile = val();
    else if (a === '--approle-mount') opts.approleMount = val();
    else if (a === '--client-certificate-path') opts.clientCertificatePath = val();
    else if (a === '--client-key-path') opts.clientKeyPath = val();
    else if (a === '--jwt-mount') opts.jwtMount = val();
    else if (a === '--import') imports.push(...splitList(val()));
    else if (a === '--base') opts.base = val();
    else if (a === '--override') opts.override = true;
    else if (a === '--keep-token') opts.keepToken = true;
    else if (a === '--timeout') opts.timeout = val();
    else if (a === '--retries') opts.retries = val();
    else if (a === '--token') throw new VaultEnvError('There is no --token option: command-line arguments are visible to every user (ps). Use VAULT_TOKEN or --token-file.', 'config');
    else if (a === '--secret-id') throw new VaultEnvError('There is no --secret-id option: command-line arguments are visible to every user (ps). Use VAULT_SECRET_ID or --secret-id-file.', 'config');
    else if (a === '--client-certificate-password') throw new VaultEnvError('There is no --client-certificate-password option: command-line arguments are visible to every user (ps). Use VAULT_CLIENT_CERTIFICATE_PASSWORD or VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE.', 'config');
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
    process.stdout.write(`${cfg.disabled ? DISABLED : NOT_CONFIGURED}\n`);
    return 0;
  }
  const result = await collect(cfg);
  const r = report(result);
  const lines = [];
  lines.push(`vault-env-loader ${VERSION}`);
  lines.push(`addr     ${cfg.addr}`);
  if (cfg.auth === 'approle') lines.push(`auth     approle (role_id ${String(cfg.roleId).slice(0, 8)}..., mount ${cfg.approleMount}; session revoked after reading)`);
  if (cfg.auth === 'certificate') lines.push(certificateCheckLine(cfg.roleId, cfg.credential.x5t, cfg.certificate, cfg.jwtMount));
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
    notLoaded(env, cfg);
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
  clientAssertion,
  VaultEnvError,
  VERSION,
  // Exposed for tests; not part of the public API.
  _internal: { readConfig, stripCredentials, parseImport, envName, mapEntries, mergeImports, plan, aliasFailures, retryable, parseArgs, main, loadClientCertificate, parseCertificateDer, audience, signAssertion, certificateStatus, certificateCheckLine },
};

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}

'use strict';
// A scriptable stand-in for Vault, run as its own process so that tests can
// exercise loadSync() (which blocks the parent's event loop).
//
//   node fake-vault.cjs <scenario.json>
// prints "PORT <n>" once listening. GET /_requests returns what it has seen.
//
// Scenario: { "token": "t", "routes": { "<path after /v1/>": response | [response, ...] } }
// A response is { "status": 200, "body": {...} } or { "delayMs": n, ... }. With an
// array, each request takes the next entry and the last one repeats.
// "approle": { "role_id": "r", "secret_id": "s" } answers POST auth/approle/login
// with "token" when the body matches (400 otherwise); a route for the login path
// takes precedence. Login needs no token. Recorded bodies mask secret_id.
// "jwt": { "role": "r", "certificate": "<PEM>"[, "mount": "jwt"] } answers POST
// auth/<mount>/login like a Vault JWT role bound to that certificate: it checks the
// header fields, x5t#S256, the signature, iss/sub/aud, the lifetime and that the jti
// is new (400 otherwise). A route entry { "verify": true } hands one request to it.
// Recorded bodies mask jwt, and carry the decoded header and claims instead.

const fs = require('fs');
const http = require('http');
const crypto = require('crypto');

const scenario = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const seen = [];
const counters = {};
const jtis = new Set();
let port;

const fromB64url = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

// Like a Vault JWT role: null when the assertion is accepted, else why not.
function checkAssertion(body, j) {
  if (!body || body.role !== j.role || typeof body.jwt !== 'string') return 'role';
  const parts = body.jwt.split('.');
  if (parts.length !== 3) return 'malformed';
  let header;
  let claims;
  try {
    header = JSON.parse(fromB64url(parts[0]));
    claims = JSON.parse(fromB64url(parts[1]));
  } catch (e) {
    return 'malformed';
  }
  if (Object.keys(header).sort().join() !== 'alg,typ,x5t#S256' || header.typ !== 'JWT') return 'header';
  const der = Buffer.from(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(j.certificate)[1].replace(/\s+/g, ''), 'base64');
  if (header['x5t#S256'] !== crypto.createHash('sha256').update(der).digest('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')) return 'x5t';
  const key = crypto.createPublicKey(j.certificate);
  const data = Buffer.from(`${parts[0]}.${parts[1]}`);
  const sig = fromB64url(parts[2]);
  const hash = { RS256: 'sha256', ES256: 'sha256', ES384: 'sha384' }[header.alg];
  if (!hash) return 'alg';
  const ok = header.alg === 'RS256' ? crypto.verify(hash, data, key, sig) : crypto.verify(hash, data, { key, dsaEncoding: 'ieee-p1363' }, sig);
  if (!ok) return 'signature';
  const now = Date.now() / 1000;
  if (claims.iss !== j.role || claims.sub !== j.role) return 'issuer';
  if (claims.aud !== `http://127.0.0.1:${port}/v1/auth/${j.mount || 'jwt'}/login`) return 'audience';
  if (!(claims.exp > now - 60) || !(claims.iat <= now + 60) || claims.exp - claims.iat > 300) return 'time';
  if (typeof claims.jti !== 'string' || claims.jti.length < 16 || jtis.has(claims.jti)) return 'jti';
  jtis.add(claims.jti);
  return null;
}

function decoded(jwt) {
  try {
    const [h, p] = jwt.split('.');
    return { header: JSON.parse(fromB64url(h)), claims: JSON.parse(fromB64url(p)) };
  } catch (e) {
    return null;
  }
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/_requests') {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(seen));
    return;
  }
  const p = decodeURIComponent(url.pathname.replace(/^\/v1\//, ''));
  let raw = '';
  req.on('data', (c) => (raw += c));
  req.on('end', () => handle(req, res, p, raw));
});

function handle(req, res, p, raw) {
  let body = null;
  try {
    body = raw ? JSON.parse(raw) : null;
  } catch (e) {
    body = 'unparseable';
  }
  let shown = body && typeof body === 'object' && 'secret_id' in body ? Object.assign({}, body, { secret_id: '***' }) : body;
  if (body && typeof body === 'object' && typeof body.jwt === 'string') shown = Object.assign({}, body, { jwt: '***' }, { assertion: decoded(body.jwt) });
  seen.push({ method: req.method, path: p, token: req.headers['x-vault-token'] || null, ua: req.headers['user-agent'] || null, ns: req.headers['x-vault-namespace'] || null, body: shown });
  const send = (status, b) => {
    res.statusCode = status;
    res.setHeader('content-type', 'application/json');
    res.end(b === undefined ? undefined : JSON.stringify(b));
  };
  const login = req.method === 'POST' && /^auth\/.+\/login$/.test(p);
  const jwtLogin = () => {
    const j = scenario.jwt;
    if (p !== `auth/${j.mount || 'jwt'}/login`) return send(404, { errors: [] });
    if (checkAssertion(body, j)) return send(400, { errors: ['invalid role or JWT'] });
    return send(200, { auth: { client_token: scenario.token, accessor: 'acc', policies: ['default'], token_policies: ['default'], lease_duration: 3600, renewable: true, metadata: { role: j.role } } });
  };
  if (login && scenario.routes[p] === undefined && scenario.jwt) return jwtLogin();
  if (login && scenario.routes[p] === undefined && scenario.approle) {
    const a = scenario.approle;
    if (p !== `auth/${a.mount || 'approle'}/login`) return send(404, { errors: [] });
    if (!body || body.role_id !== a.role_id || (a.secret_id !== undefined && body.secret_id !== a.secret_id)) return send(400, { errors: ['invalid role or secret ID'] });
    return send(200, { auth: { client_token: scenario.token, accessor: 'acc', policies: ['default'], token_policies: ['default'], lease_duration: 3600, renewable: true, metadata: { role_name: 'r' } } });
  }
  if (!login && scenario.token && req.headers['x-vault-token'] !== scenario.token) return send(403, { errors: ['permission denied'] });
  let r = scenario.routes[p];
  if (r === undefined) return send(404, { errors: [] });
  if (Array.isArray(r)) {
    const i = counters[p] || 0;
    counters[p] = i + 1;
    r = r[Math.min(i, r.length - 1)];
  }
  if (r.hang) return; // never answers: exercises the client timeout
  if (r.verify) return jwtLogin();
  setTimeout(() => send(r.status || 200, r.body), r.delayMs || 0);
}

server.listen(0, '127.0.0.1', () => {
  port = server.address().port;
  process.stdout.write(`PORT ${server.address().port}\n`);
});

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

const fs = require('fs');
const http = require('http');

const scenario = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const seen = [];
const counters = {};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/_requests') {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(seen));
    return;
  }
  const p = decodeURIComponent(url.pathname.replace(/^\/v1\//, ''));
  seen.push({ method: req.method, path: p, token: req.headers['x-vault-token'] || null, ua: req.headers['user-agent'] || null, ns: req.headers['x-vault-namespace'] || null });
  const send = (status, body) => {
    res.statusCode = status;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(body));
  };
  if (scenario.token && req.headers['x-vault-token'] !== scenario.token) return send(403, { errors: ['permission denied'] });
  let r = scenario.routes[p];
  if (r === undefined) return send(404, { errors: [] });
  if (Array.isArray(r)) {
    const i = counters[p] || 0;
    counters[p] = i + 1;
    r = r[Math.min(i, r.length - 1)];
  }
  if (r.hang) return; // never answers: exercises the client timeout
  setTimeout(() => send(r.status || 200, r.body), r.delayMs || 0);
});

server.listen(0, '127.0.0.1', () => {
  process.stdout.write(`PORT ${server.address().port}\n`);
});

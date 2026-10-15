#!/usr/bin/env python3
"""vault-env-loader: load HashiCorp Vault KV secrets into environment variables
before your application starts.

One file, zero dependencies, Python >= 3.6. It is at the same time:
  - the CLI:     vault-env-loader [options] -- <command...>
                 python -m vault_env_loader [options] -- <command...>
  - the library: load() / fetch()

Behaviour follows the Node.js package of the same name; both run the shared
cases in spec/cases.json. Secret values never go to logs, error messages, argv
or disk.
"""

import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = '0.1.0'
__all__ = ['load', 'fetch', 'VaultEnvError', '__version__']

TAG = '[vault-env-loader]'
EX_CONFIG = 78
LOADED_MARK = 'VAULT_ENV_LOADED'
TTL_WARN_SECONDS = 14 * 24 * 3600
# Linux MAX_ARG_STRLEN: one "NAME=value\0" string handed to execve.
MAX_ENV_STRING = 128 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
VALID_ENV_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
NAME_MODES = ('auto', 'verbatim', 'upper')
# Some Vault-compatible servers that resolve keys from other stores answer 502
# with "alias 'x' could not be resolved: <reason>" per failed key.
TRANSIENT_ALIAS_REASONS = ('timeout', 'unavailable')
ALIAS_FAILURE = re.compile(r"^alias '(.+)' could not be resolved: ([a-z_]+)$")
TRUTHY = ('1', 'true', 'yes', 'on')
FALSY = ('0', 'false', 'no', 'off')


class VaultEnvError(Exception):
    """A configuration or Vault error. Messages name paths and keys, never values or tokens."""

    def __init__(self, message, code='error'):
        super(VaultEnvError, self).__init__(message)
        self.message = message
        self.code = code


def warn(message):
    sys.stderr.write('%s %s\n' % (TAG, message))
    sys.stderr.flush()


def truthy(v):
    return isinstance(v, str) and v.strip().lower() in TRUTHY


def non_empty(v):
    return v.strip() if isinstance(v, str) and v.strip() != '' else None


# ---------------------------------------------------------------------------
# Configuration

def read_config(options=None, env=None):
    options = options or {}
    env = os.environ if env is None else env

    def pick(opt, *names):
        if options.get(opt) is not None:
            return options[opt]
        for n in names:
            if non_empty(env.get(n)) is not None:
                return env[n]
        return None

    skip = non_empty(env.get('VAULT_SKIP_VERIFY'))
    if skip is not None and skip.lower() not in FALSY:
        raise VaultEnvError('VAULT_SKIP_VERIFY is set, but vault-env-loader never skips TLS verification. '
                            'Unset it and point VAULT_CACERT at your CA instead.', 'config')

    addr = non_empty(pick('addr', 'VAULT_ADDR'))
    imports = pick('imports', 'VAULT_ENV_IMPORT')
    if isinstance(imports, str):
        imports = split_list(imports)
    imports = [str(s).strip() for s in (imports or []) if str(s).strip()]

    token_file = non_empty(pick('token_file', 'VAULT_TOKEN_FILE'))
    token = options['token'] if options.get('token') is not None else non_empty(env.get('VAULT_TOKEN'))

    if not addr and not imports:
        return {'configured': False}

    if not addr:
        raise VaultEnvError('VAULT_ADDR is not set (VAULT_ENV_IMPORT is).', 'config')
    if not imports:
        raise VaultEnvError('VAULT_ENV_IMPORT is empty: name at least one path to load.', 'config')
    if not token and token_file:
        try:
            with open(token_file, 'r', encoding='utf-8') as f:
                token = f.read().strip()
        except OSError as e:
            raise VaultEnvError('Cannot read VAULT_TOKEN_FILE (%s): %s.' % (token_file, _errno_name(e)), 'config')
        if not token:
            raise VaultEnvError('VAULT_TOKEN_FILE (%s) is empty.' % token_file, 'config')
    if not token:
        raise VaultEnvError('No token: set VAULT_TOKEN or VAULT_TOKEN_FILE.', 'config')

    url = urllib.parse.urlsplit(addr)
    if url.scheme not in ('http', 'https') or not url.hostname:
        if url.scheme and url.scheme not in ('http', 'https'):
            raise VaultEnvError('VAULT_ADDR must start with https://', 'config')
        raise VaultEnvError('VAULT_ADDR is not a valid URL.', 'config')
    allow_http = bool(options['allow_http']) if options.get('allow_http') is not None else truthy(env.get('VAULT_ENV_ALLOW_HTTP'))
    if url.scheme == 'http' and not is_loopback(url.hostname) and not allow_http:
        raise VaultEnvError('VAULT_ADDR uses plain http to %s; use https, or set VAULT_ENV_ALLOW_HTTP=true '
                            'if this network really has no TLS.' % url.hostname, 'config')

    def num(v, default, name):
        if v is None or v == '':
            return default
        try:
            n = float(v)
        except (TypeError, ValueError):
            n = -1
        if n != n or n < 0 or n == float('inf'):
            raise VaultEnvError('%s must be a non-negative number.' % name, 'config')
        return n

    def flag(opt, var):
        return bool(options[opt]) if options.get(opt) is not None else truthy(env.get(var))

    return {
        'configured': True,
        'addr': addr.rstrip('/'),
        'insecure_http': url.scheme == 'http' and not is_loopback(url.hostname),
        'token': token,
        'token_from_file': non_empty(env.get('VAULT_TOKEN')) is None and options.get('token') is None and bool(token_file),
        'namespace': non_empty(pick('namespace', 'VAULT_NAMESPACE')),
        'ssl_context': ssl_context(non_empty(pick('cacert', 'VAULT_CACERT')), non_empty(pick('capath', 'VAULT_CAPATH'))),
        'imports': [parse_import(i) for i in imports],
        'base': non_empty(pick('base', 'VAULT_ENV_BASE')),
        'override': flag('override', 'VAULT_ENV_OVERRIDE'),
        'keep_token': flag('keep_token', 'VAULT_ENV_KEEP_TOKEN'),
        'timeout': num(pick('timeout', 'VAULT_ENV_TIMEOUT'), 10, 'VAULT_ENV_TIMEOUT'),
        'retries': int(num(pick('retries', 'VAULT_ENV_RETRIES'), 3, 'VAULT_ENV_RETRIES')),
        'retry_delay': options['retry_delay'] if options.get('retry_delay') is not None else 1.0,
        'case_insensitive': bool(options['case_insensitive']) if options.get('case_insensitive') is not None else os.name == 'nt',
    }


def is_loopback(host):
    return host in ('localhost', '127.0.0.1', '::1')


def split_list(s):
    return re.split(r'[,\n]', s)


def _errno_name(e):
    import errno
    return errno.errorcode.get(getattr(e, 'errno', None) or 0, 'error')


def ssl_context(cafile, capath):
    """The system trust store plus VAULT_CACERT / every *.pem and *.crt in VAULT_CAPATH."""
    ctx = ssl.create_default_context()
    if cafile:
        try:
            ctx.load_verify_locations(cafile=cafile)
        except (OSError, ssl.SSLError) as e:
            raise VaultEnvError('Cannot read VAULT_CACERT (%s): %s.' % (cafile, _errno_name(e)), 'config')
    if capath:
        # OpenSSL's capath wants hashed file names; read the files ourselves, like the Node package.
        try:
            names = sorted(os.listdir(capath))
        except OSError as e:
            raise VaultEnvError('Cannot read VAULT_CAPATH (%s): %s.' % (capath, _errno_name(e)), 'config')
        for n in names:
            if re.search(r'\.(pem|crt)$', n, re.I):
                try:
                    with open(os.path.join(capath, n), 'r', encoding='utf-8') as f:
                        ctx.load_verify_locations(cadata=f.read())
                except (OSError, ssl.SSLError, ValueError):
                    raise VaultEnvError('Cannot load certificate %s from VAULT_CAPATH.' % n, 'config')
    return ctx


# ---------------------------------------------------------------------------
# Imports:  [optional:]location[?prefix=..&name=auto|verbatim|upper&kv=1|2]
#   vault://<mount>/<path>   absolute (same as Spring Cloud Vault)
#   vault://                 the base path itself
#   <path>                   relative to the base path

def parse_import(raw):
    spec = raw.strip()
    optional = False
    if spec.startswith('optional:'):
        optional = True
        spec = spec[len('optional:'):].strip()
    query = ''
    q = spec.find('?')
    if q >= 0:
        query = spec[q + 1:]
        spec = spec[:q]
    prefix, name, kv = '', 'auto', None
    for part in query.split('&') if query else []:
        if not part:
            continue
        k, _, v = part.partition('=')
        k, v = urllib.parse.unquote(k), urllib.parse.unquote(v)
        if k == 'prefix':
            prefix = v
        elif k == 'name':
            if v not in NAME_MODES:
                raise VaultEnvError('Import "%s": name must be one of %s.' % (raw, ', '.join(NAME_MODES)), 'config')
            name = v
        elif k == 'kv':
            if v not in ('1', '2'):
                raise VaultEnvError('Import "%s": kv must be 1 or 2.' % raw, 'config')
            kv = int(v)
        else:
            raise VaultEnvError('Import "%s": unknown option "%s" (known: prefix, name, kv).' % (raw, k), 'config')
    if name != 'verbatim' and not re.match(r'^[A-Za-z0-9_]*$', prefix):
        raise VaultEnvError('Import "%s": prefix may only contain letters, digits and _.' % raw, 'config')

    if spec in ('vault://', 'vault:'):
        kind, p = 'base', ''
    elif spec.startswith('vault://'):
        kind, p = 'absolute', spec[len('vault://'):]
    elif '://' in spec:
        raise VaultEnvError('Import "%s": only vault:// locations are supported.' % raw, 'config')
    else:
        kind, p = 'relative', spec
    p = p.strip('/')
    if kind != 'base' and not p:
        raise VaultEnvError('Import "%s": empty path.' % raw, 'config')
    if p and any(s in ('', '.', '..') for s in p.split('/')):
        raise VaultEnvError('Import "%s": path segments may not be empty, "." or "..".' % raw, 'config')
    if kind == 'absolute' and '/' not in p:
        raise VaultEnvError('Import "%s": expected vault://<mount>/<path>.' % raw, 'config')
    return {'raw': raw, 'optional': optional, 'kind': kind, 'path': p, 'prefix': prefix, 'name': name, 'kv': kv}


# ---------------------------------------------------------------------------
# HTTP

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # urllib would follow a 3xx and send X-Vault-Token to wherever it points.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _NetworkError(Exception):
    def __init__(self, what):
        super(_NetworkError, self).__init__(what)
        self.what = what


def encode_path(p):
    return '/'.join(urllib.parse.quote(s, safe='') for s in p.split('/'))


def _opener(cfg):
    if '_opener' not in cfg:
        # Proxies come from HTTPS_PROXY / HTTP_PROXY / NO_PROXY, as everywhere in Python.
        cfg['_opener'] = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=cfg['ssl_context']))
    return cfg['_opener']


def http_get(cfg, api_path):
    """GET <addr>/v1/<api_path> -> (status, parsed JSON body or None). Raises _NetworkError."""
    headers = {
        'X-Vault-Token': cfg['token'],
        'X-Vault-Request': 'true',
        'User-Agent': 'vault-env-loader/%s python/%s' % (__version__, '.'.join(map(str, sys.version_info[:3]))),
        'Accept': 'application/json',
    }
    if cfg.get('namespace'):
        headers['X-Vault-Namespace'] = cfg['namespace']
    req = urllib.request.Request('%s/v1/%s' % (cfg['addr'], api_path), headers=headers, method='GET')
    try:
        resp = _opener(cfg).open(req, timeout=cfg['timeout'])
    except urllib.error.HTTPError as e:
        resp = e
    except socket.timeout:
        raise _NetworkError('timed out')
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, socket.timeout):
            raise _NetworkError('timed out')
        if isinstance(reason, ssl.SSLError):
            raise _NetworkError('failed (TLS: %s)' % (getattr(reason, 'reason', None) or 'certificate verification failed'))
        raise _NetworkError('failed (%s)' % (_errno_name(reason) if isinstance(reason, OSError) else 'network error'))
    except (OSError, ValueError, http.client.HTTPException) as e:
        raise _NetworkError('failed (%s)' % (_errno_name(e) if isinstance(e, OSError) else type(e).__name__))
    try:
        status = resp.getcode()
        try:
            data = resp.read(MAX_RESPONSE_BYTES + 1)
        except socket.timeout:
            raise _NetworkError('timed out')
        except OSError as e:
            raise _NetworkError('failed (%s)' % _errno_name(e))
        except http.client.HTTPException as e:
            raise _NetworkError('failed (%s)' % type(e).__name__)
        if len(data) > MAX_RESPONSE_BYTES:
            raise _NetworkError('failed (response too large)')
    finally:
        resp.close()
    try:
        body = json.loads(data.decode('utf-8')) if data else None
    except ValueError:
        body = None
    return status, body


def alias_failures(body):
    errors = body.get('errors') if isinstance(body, dict) else None
    out = []
    for e in errors if isinstance(errors, list) else []:
        m = ALIAS_FAILURE.match(str(e))
        if m:
            out.append({'alias': m.group(1), 'reason': m.group(2)})
    return out


def retryable(status, body):
    if status in (429, 500, 503, 504):
        return True
    if status == 502:
        failures = alias_failures(body)
        return not failures or all(f['reason'] in TRANSIENT_ALIAS_REASONS for f in failures)
    return False


def get_with_retry(cfg, api_path):
    """GET with retries on transient failures; returns the final (status, body)."""
    attempt = 0
    while True:
        res, net_err = None, None
        try:
            res = http_get(cfg, api_path)
        except _NetworkError as e:
            net_err = e
        if res is not None and not retryable(*res):
            return res
        if attempt >= cfg['retries']:
            if res is not None:
                return res
            hint = '' if net_err.what == 'timed out' else _proxy_hint(cfg)
            raise VaultEnvError('Request to Vault %s.%s' % (net_err.what, hint), 'unavailable')
        time.sleep(cfg['retry_delay'] * (2 ** attempt))
        attempt += 1


def _proxy_hint(cfg):
    host = urllib.parse.urlsplit(cfg['addr']).hostname
    proxies = urllib.request.getproxies()
    scheme = urllib.parse.urlsplit(cfg['addr']).scheme
    if proxies.get(scheme) and not urllib.request.proxy_bypass(host):
        return ' The request went through the proxy in %s_PROXY; add %s to NO_PROXY if Vault is reachable directly.' % (scheme.upper(), host)
    return ''


# ---------------------------------------------------------------------------
# Vault reads

def lookup_self(cfg):
    status, body = get_with_retry(cfg, 'auth/token/lookup-self')
    if status in (401, 403):
        return {'denied': True, 'ttl': 0, 'meta': {}}
    if status != 200 or not isinstance(body, dict) or not isinstance(body.get('data'), dict):
        return None
    d = body['data']
    ttl = d.get('ttl')
    meta = d.get('meta')
    return {
        'denied': False,
        'ttl': ttl if isinstance(ttl, (int, float)) and not isinstance(ttl, bool) else 0,
        'meta': meta if isinstance(meta, dict) else {},
    }


def resolve_base(cfg, me):
    if cfg.get('base'):
        return {'base': cfg['base'].strip('/'), 'source': 'VAULT_ENV_BASE'}
    m = me and me.get('meta') or {}
    app, env = non_empty(m.get('application')), non_empty(m.get('environment'))
    if app and env:
        return {'base': 'secret/%s/%s' % (m['application'], m['environment']), 'source': 'token metadata',
                'app': m['application'], 'env': m['environment']}
    return {'base': None, 'source': None, 'denied': bool(me and me.get('denied'))}


def full_path(imp, base_info):
    if imp['kind'] == 'absolute':
        if base_info.get('source') == 'token metadata':
            seg = imp['path'].split('/') + ['', '']
            if seg[0] == 'secret' and (seg[1] != base_info['app'] or seg[2] != base_info['env']):
                raise VaultEnvError(
                    'Import "%s" points at %s/%s, but this token belongs to %s/%s. A token can only read its own '
                    'application and environment.' % (imp['raw'], seg[1] or '?', seg[2] or '?',
                                                      base_info['app'], base_info['env']), 'config')
        return imp['path']
    if not base_info.get('base'):
        if base_info.get('denied'):
            raise VaultEnvError(
                'Import "%s" is relative, and Vault refused to describe the token (permission denied on '
                'auth/token/lookup-self): the token is invalid, expired or revoked, its IP is not allowed, or its '
                'policy lacks lookup-self. Set VAULT_ENV_BASE or write vault://<mount>/<path> if the policy is '
                'intended.' % imp['raw'], 'auth')
        raise VaultEnvError('Import "%s" is relative, but there is no base path: set VAULT_ENV_BASE or write '
                            'vault://<mount>/<path>.' % imp['raw'], 'config')
    return base_info['base'] if imp['kind'] == 'base' else '%s/%s' % (base_info['base'], imp['path'])


def locate(cfg, imp, p):
    """Learn the mount and KV version the way `vault kv get` does."""
    first = p.split('/')[0]
    fallback = {'mount': first, 'rest': p[len(first) + 1:], 'kv': imp['kv'] or 2, 'probed': False}
    if imp['kv']:
        return fallback
    status, body = get_with_retry(cfg, 'sys/internal/ui/mounts/%s' % encode_path(p))
    d = body.get('data') if status == 200 and isinstance(body, dict) else None
    if not isinstance(d, dict):
        return fallback
    mount = d['path'].rstrip('/') if isinstance(d.get('path'), str) and d['path'] else first
    if p != mount and not p.startswith(mount + '/'):
        return fallback
    options = d.get('options') if isinstance(d.get('options'), dict) else {}
    if str(options.get('version')) == '2':
        version = 2
    elif d.get('type') in ('kv', 'generic'):
        version = 1
    else:
        version = 2
    return {'mount': mount, 'rest': p[len(mount) + 1:], 'kv': version, 'probed': True}


def describe_status(status, body, imp, p, loc):
    where = '"%s" (%s)' % (imp['raw'], p)
    if status in (401, 403):
        return VaultEnvError('Permission denied reading %s: the token is invalid, expired or revoked, its IP is not '
                             'allowed, or its policy does not allow reading this path.' % where, 'auth')
    if status == 404:
        other = 1 if loc['kv'] == 2 else 2
        hint = '' if loc['probed'] else ' If this is a KV version %d mount, add ?kv=%d.' % (other, other)
        return VaultEnvError('Not found: %s.%s' % (where, hint), 'not_found')
    failures = alias_failures(body) if status == 502 else []
    if failures:
        listed = ', '.join('%s (%s)' % (f['alias'], f['reason']) for f in failures)
        return VaultEnvError('Vault could not resolve %s: %s.' % (where, listed), 'resolve')
    return VaultEnvError('Vault answered HTTP %s for %s.' % (status, where), 'unavailable')


def read_import(cfg, imp, base_info):
    p = full_path(imp, base_info)
    loc = locate(cfg, imp, p)
    if loc['kv'] == 2:
        api_path = '%s/data/%s' % (encode_path(loc['mount']), encode_path(loc['rest']))
    else:
        api_path = encode_path(p)
    status, body = get_with_retry(cfg, api_path)
    if status == 200 and isinstance(body, dict) and isinstance(body.get('data'), dict):
        outer = body['data']
        data = outer.get('data') if loc['kv'] == 2 else outer
        meta = outer.get('metadata') if loc['kv'] == 2 else None
        version = meta.get('version') if isinstance(meta, dict) else None
        if isinstance(data, dict):
            return {'path': p, 'kv': loc['kv'], 'version': version, 'data': data}
        # KV v2 answers 200 with data: null for a deleted latest version.
        if loc['kv'] == 2:
            return {'path': p, 'kv': loc['kv'], 'missing': True}
    if status == 404 and imp['optional']:
        return {'path': p, 'kv': loc['kv'], 'missing': True}
    raise describe_status(status, body, imp, p, loc)


# ---------------------------------------------------------------------------
# Key -> environment variable names

def env_name(key, mode):
    if mode == 'verbatim':
        return key
    if mode == 'auto' and VALID_ENV_NAME.match(key):
        return key
    n = re.sub(r'[^A-Za-z0-9_]', '_', key).upper()
    if re.match(r'^[0-9]', n):
        n = '_' + n
    return n


def string_value(v):
    if isinstance(v, str):
        return v
    if v is None:
        return ''
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e21:
        v = int(v)  # JSON has one number type: 1.0 is written 1, as in JavaScript
    return json.dumps(v, separators=(',', ':'), ensure_ascii=False)


def map_entries(data, imp, case_insensitive):
    """One import's data -> [{key, name, value}]. Fails on collisions and on values an
    environment cannot carry. Errors name keys, never values."""
    entries = []
    seen = {}
    for key in data:
        name = imp['prefix'] + env_name(key, imp['name'])
        if not name or '=' in name or '\0' in name:
            raise VaultEnvError('Key "%s" in "%s" cannot be used as an environment variable name; use ?name=auto '
                                'or ?name=upper.' % (key, imp['raw']), 'value')
        cmp = name.upper() if case_insensitive else name
        if cmp in seen:
            raise VaultEnvError('Keys "%s" and "%s" in "%s" both become %s. Rename one of them in Vault, or choose '
                                'another ?name= mode.' % (seen[cmp], key, imp['raw'], name), 'collision')
        seen[cmp] = key
        value = string_value(data[key])
        if '\0' in value:
            raise VaultEnvError('The value of "%s" in "%s" contains a NUL byte, which an environment variable cannot '
                                'hold.' % (key, imp['raw']), 'value')
        if len(name.encode('utf-8')) + 1 + len(value.encode('utf-8', 'surrogatepass')) + 1 > MAX_ENV_STRING:
            raise VaultEnvError('The value of "%s" in "%s" is larger than 128 KB, the limit for one environment '
                                'variable.' % (key, imp['raw']), 'value')
        entries.append({'key': key, 'name': name, 'value': value})
    return entries


def merge_imports(results, case_insensitive):
    """Later imports win over earlier ones. Returns the merged values and the overridden names."""
    values = {}
    canonical = {}
    overridden = []
    for r in results:
        for e in r.get('entries') or []:
            cmp = e['name'].upper() if case_insensitive else e['name']
            if cmp in canonical:
                del values[canonical[cmp]]
                if e['name'] not in overridden:
                    overridden.append(e['name'])
            canonical[cmp] = e['name']
            values[e['name']] = e['value']
    return {'values': values, 'overridden': overridden}


def plan(values, env, override):
    """Decide what to write into env. Existing variables win unless override."""
    to_set = {}
    kept = []
    for name in values:
        if not override and env.get(name) is not None:
            kept.append(name)
        else:
            to_set[name] = values[name]
    return {'set': to_set, 'kept': kept}


# ---------------------------------------------------------------------------
# Pipeline

def collect(cfg):
    warnings = []
    if cfg['insecure_http']:
        warnings.append('VAULT_ADDR uses plain http: the token and every secret cross the network unencrypted.')
    me = lookup_self(cfg)
    if me and not me['denied'] and 0 < me['ttl'] < TTL_WARN_SECONDS:
        warnings.append('The token expires in %d day(s). Issue a new one before then.' % max(1, round(me['ttl'] / 86400.0)))
    base_info = resolve_base(cfg, me)
    results = []
    for imp in cfg['imports']:
        r = read_import(cfg, imp, base_info)
        if r.get('missing'):
            if not imp['optional']:
                raise VaultEnvError('Not found: "%s" (%s).' % (imp['raw'], r['path']), 'not_found')
            results.append({'raw': imp['raw'], 'path': r['path'], 'kv': r['kv'], 'skipped': True, 'entries': []})
            continue
        results.append({'raw': imp['raw'], 'path': r['path'], 'kv': r['kv'], 'version': r['version'],
                        'entries': map_entries(r['data'], imp, cfg['case_insensitive'])})
    merged = merge_imports(results, cfg['case_insensitive'])
    if merged['overridden']:
        warnings.append('Set by more than one import (the later one wins): %s.' % ', '.join(merged['overridden']))
    return {'self': me, 'base_info': base_info, 'results': results, 'values': merged['values'], 'warnings': warnings}


def apply(values, env, cfg):
    p = plan(values, env, cfg['override'])
    for name, value in p['set'].items():
        env[name] = value
    if p['kept']:
        warn('Already set in the environment, kept as is (set VAULT_ENV_OVERRIDE=true to replace): %s.' % ', '.join(p['kept']))
    env[LOADED_MARK] = '1'
    if not cfg['keep_token']:
        env.pop('VAULT_TOKEN', None)
        if cfg['token_from_file']:
            env.pop('VAULT_TOKEN_FILE', None)
    return list(p['set'])


NOT_CONFIGURED = 'VAULT_ADDR and VAULT_ENV_IMPORT are not set; nothing loaded from Vault.'


# ---------------------------------------------------------------------------
# Library API

def fetch(env=None, **options):
    """Read the configured imports and return {NAME: value} without touching the environment.

    Keyword options mirror the environment variables: addr, token, token_file, imports, base,
    namespace, cacert, capath, timeout, retries, allow_http.
    """
    cfg = read_config(options, os.environ if env is None else env)
    if not cfg['configured']:
        raise VaultEnvError(NOT_CONFIGURED, 'config')
    result = collect(cfg)
    for w in result['warnings']:
        warn(w)
    return result['values']


def load(env=None, **options):
    """Load into os.environ (or `env`). Returns the names that were set.

    Call it before anything reads the configuration. Does nothing when VAULT_ENV_LOADED is
    already set (for example by the vault-env-loader wrapper). Keyword options as for fetch(),
    plus override and keep_token.
    """
    env = os.environ if env is None else env
    if env.get(LOADED_MARK):
        return []
    cfg = read_config(options, env)
    if not cfg['configured']:
        warn(NOT_CONFIGURED)
        return []
    result = collect(cfg)
    for w in result['warnings']:
        warn(w)
    return apply(result['values'], env, cfg)


# ---------------------------------------------------------------------------
# CLI

HELP = """vault-env-loader %s - load Vault KV secrets into environment variables, then run a command.

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
""" % __version__


def parse_args(argv):
    opts = {}
    imports = []
    command = None
    sub = None
    i = 0
    while i < len(argv):
        a = argv[i]

        def val():
            if i + 1 >= len(argv):
                raise VaultEnvError('%s needs a value.' % a, 'config')
            return argv[i + 1]

        if a == '--':
            command = argv[i + 1:]
            break
        elif a in ('--addr', '--token-file', '--import', '--base', '--timeout', '--retries'):
            v = val()
            i += 1
            if a == '--import':
                imports.extend(split_list(v))
            else:
                opts[a[2:].replace('-', '_')] = v
        elif a == '--override':
            opts['override'] = True
        elif a == '--keep-token':
            opts['keep_token'] = True
        elif a == '--token':
            raise VaultEnvError('There is no --token option: command-line arguments are visible to every user (ps). '
                                'Use VAULT_TOKEN or --token-file.', 'config')
        elif a == 'check' and sub is None:
            sub = 'check'
        elif a in ('--version', '-v'):
            sub = 'version'
        elif a in ('--help', '-h'):
            sub = 'help'
        elif not a.startswith('-') and sub is None:
            # Allow "vault-env-loader gunicorn app:app" without "--".
            command = argv[i:]
            break
        else:
            raise VaultEnvError('Unknown option %s. See --help.' % a, 'config')
        i += 1
    if imports:
        opts['imports'] = imports
    return {'opts': opts, 'command': command, 'sub': sub}


def check(opts):
    cfg = read_config(opts, os.environ)
    if not cfg['configured']:
        sys.stdout.write(NOT_CONFIGURED + '\n')
        return 0
    result = collect(cfg)
    me = result['self']
    base_info = result['base_info']
    lines = ['vault-env-loader %s' % __version__, 'addr     %s' % cfg['addr']]
    if me and not me['denied']:
        meta = ' '.join('%s=%s' % (k, v) for k, v in me['meta'].items())
        expiry = 'expires in %dh' % round(me['ttl'] / 3600.0) if me['ttl'] else 'no expiry'
        lines.append('token    %s%s' % (expiry, ', ' + meta if meta else ''))
    else:
        lines.append('token    (lookup-self not permitted)')
    lines.append('base     %s' % ('%s (from %s)' % (base_info['base'], base_info['source']) if base_info.get('base') else '(none)'))
    kept = plan(result['values'], os.environ, cfg['override'])['kept']

    def canon(n):
        return n.upper() if cfg['case_insensitive'] else n

    last_import = {}
    for i, r in enumerate(result['results']):
        for e in r['entries']:
            last_import[canon(e['name'])] = i
    for i, r in enumerate(result['results']):
        lines.append('')
        version = ', version %s' % r['version'] if r.get('version') is not None else ''
        skipped = '  [optional, not found: skipped]' if r.get('skipped') else ''
        lines.append('import   %s  ->  %s  (kv v%s%s)%s' % (r['raw'], r['path'], r['kv'], version, skipped))
        width = max([len(e['name']) for e in r['entries']] or [0])
        for e in r['entries']:
            notes = []
            if e['name'] != e['key']:
                notes.append('from %s' % e['key'])
            if last_import.get(canon(e['name'])) != i:
                notes.append('overridden by a later import')
            elif e['name'] in kept:
                notes.append('already set: kept')
            lines.append('  %s  %5d chars%s' % (e['name'].ljust(width), len(e['value']), '  (%s)' % '; '.join(notes) if notes else ''))
    for w in result['warnings']:
        warn(w)
    sys.stdout.write('\n'.join(lines) + '\n')
    return 0


def run(opts, command):
    env = dict(os.environ)
    if not env.get(LOADED_MARK):
        cfg = read_config(opts, env)
        if not cfg['configured']:
            warn(NOT_CONFIGURED)
        else:
            result = collect(cfg)
            for w in result['warnings']:
                warn(w)
            apply(result['values'], env, cfg)
    return execute(command, env)


def execute(command, env):
    sys.stdout.flush()
    sys.stderr.flush()
    if os.name != 'nt':
        # Replace this process: same PID, signals and exit status need no forwarding.
        try:
            os.execvpe(command[0], command, env)
        except FileNotFoundError:
            warn('Command not found: %s' % command[0])
            return 127
        except OSError as e:
            warn('Could not start %s: %s' % (command[0], _errno_name(e)))
            return 126
    # Windows has no exec: run the command and pass its exit code through. Ctrl+C reaches
    # the whole console group, so the child gets it too; we only wait for it.
    try:
        child = subprocess.Popen(command, env=env)
    except FileNotFoundError:
        warn('Command not found: %s' % command[0])
        return 127
    except OSError as e:
        warn('Could not start %s: %s' % (command[0], _errno_name(e)))
        return 126
    while True:
        try:
            return child.wait()
        except KeyboardInterrupt:
            continue


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        parsed = parse_args(argv)
        if parsed['sub'] == 'version':
            sys.stdout.write(__version__ + '\n')
            return 0
        if parsed['sub'] == 'help' or (not parsed['sub'] and not parsed['command']):
            sys.stdout.write(HELP)
            return 0 if parsed['sub'] == 'help' else 2
        if parsed['sub'] == 'check':
            return check(parsed['opts'])
        if not parsed['command']:
            raise VaultEnvError('No command given after --.', 'config')
        return run(parsed['opts'], parsed['command'])
    except VaultEnvError as e:
        warn(e.message)
        return EX_CONFIG
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # never print a traceback that could carry request data
        warn('Unexpected error: %s' % type(e).__name__)
        return EX_CONFIG


def _cli():
    sys.exit(main())


if __name__ == '__main__':
    _cli()

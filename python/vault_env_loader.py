#!/usr/bin/env python3
"""vault-env-loader: load HashiCorp Vault KV secrets into environment variables
before your application starts.

One file, zero dependencies, Python >= 3.6. It is at the same time:
  - the CLI:     vault-env-loader [options] -- <command...>
                 python -m vault_env_loader [options] -- <command...>
  - the library: load() / fetch() / client_assertion()

Certificate login (and client_assertion) needs the optional cryptography package:
pip install "vault-env-loader[cert]". It is imported only when that method is used.

Behaviour follows the Node.js package of the same name; both run the shared
cases in spec/cases.json. Secret values never go to logs, error messages, argv
or disk.
"""

import base64
import calendar
import hashlib
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
import warnings

__version__ = '0.4.0'
__all__ = ['load', 'fetch', 'client_assertion', 'VaultEnvError', '__version__']

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
APPROLE_MOUNT = re.compile(r'^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$')
ASSERTION_LIFETIME = 120
CERT_WARN_DAYS = 30


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
    enabled = enabled_switch(env)

    addr = non_empty(pick('addr', 'VAULT_ADDR'))
    imports = pick('imports', 'VAULT_ENV_IMPORT')
    if isinstance(imports, str):
        imports = split_list(imports)
    imports = [str(s).strip() for s in (imports or []) if str(s).strip()]

    token_file = non_empty(pick('token_file', 'VAULT_TOKEN_FILE'))
    token = options['token'] if options.get('token') is not None else non_empty(env.get('VAULT_TOKEN'))
    role_id_file = non_empty(pick('role_id_file', 'VAULT_ROLE_ID_FILE'))
    role_id = non_empty(options['role_id']) if options.get('role_id') is not None else non_empty(env.get('VAULT_ROLE_ID'))
    secret_id_file = non_empty(pick('secret_id_file', 'VAULT_SECRET_ID_FILE'))
    secret_id = non_empty(options['secret_id']) if options.get('secret_id') is not None else non_empty(env.get('VAULT_SECRET_ID'))
    approle_given = bool(role_id or role_id_file or secret_id or secret_id_file)
    # Certificate login: only VAULT_CLIENT_CERTIFICATE_PATH selects it. A key path or
    # password without it changes nothing, as in 0.3. The password is taken as it is.
    cert_path = non_empty(pick('client_certificate_path', 'VAULT_CLIENT_CERTIFICATE_PATH'))
    key_path = non_empty(pick('client_key_path', 'VAULT_CLIENT_KEY_PATH')) if cert_path else None
    password_given = options.get('client_certificate_password') is not None
    password = str(options['client_certificate_password']) if password_given else env.get('VAULT_CLIENT_CERTIFICATE_PASSWORD')
    if password == '':
        password = None
    password_file = non_empty(pick('client_certificate_password_file', 'VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE'))

    # A token, when there is one, is used exactly as before AppRole support; AppRole
    # variables beside it are left alone (they may be meant for another tool).
    # Decided from what is set, before any file is read, so that a disabled run
    # removes the same variables a load would.
    if token or token_file:
        auth = 'token'
    elif cert_path and (role_id or role_id_file) and not (secret_id or secret_id_file):
        auth = 'certificate'
    else:
        auth = 'approle'
    used = []
    if auth != 'token':
        if role_id:
            if options.get('role_id') is None:
                used.append('VAULT_ROLE_ID')
        elif role_id_file and options.get('role_id_file') is None:
            used.append('VAULT_ROLE_ID_FILE')
        if secret_id:
            if options.get('secret_id') is None:
                used.append('VAULT_SECRET_ID')
        elif secret_id_file and options.get('secret_id_file') is None:
            used.append('VAULT_SECRET_ID_FILE')
        if cert_path:
            if options.get('client_certificate_path') is None:
                used.append('VAULT_CLIENT_CERTIFICATE_PATH')
            if key_path and options.get('client_key_path') is None:
                used.append('VAULT_CLIENT_KEY_PATH')
            if password is not None:
                if not password_given:
                    used.append('VAULT_CLIENT_CERTIFICATE_PASSWORD')
            elif password_file and options.get('client_certificate_password_file') is None:
                used.append('VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE')
    token_from_file = auth == 'token' and non_empty(env.get('VAULT_TOKEN')) is None and options.get('token') is None and bool(token_file)

    def flag(opt, var):
        return bool(options[opt]) if options.get(opt) is not None else truthy(env.get(var))

    keep_token = flag('keep_token', 'VAULT_ENV_KEEP_TOKEN')
    if enabled is False:
        return {'configured': False, 'disabled': True, 'keep_token': keep_token,
                'token_from_file': token_from_file, 'approle_vars_used': used}

    if not addr and not imports:
        if enabled:
            raise VaultEnvError(ENABLED_NOT_CONFIGURED, 'config')
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
    notes = []
    if auth == 'token':
        if cert_path:
            notes.append('VAULT_TOKEN is set, so VAULT_ROLE_ID / VAULT_SECRET_ID / VAULT_CLIENT_CERTIFICATE_PATH are ignored.')
        elif approle_given:
            notes.append('VAULT_TOKEN is set, so VAULT_ROLE_ID / VAULT_SECRET_ID are ignored.')
    elif role_id or role_id_file:
        if cert_path and auth != 'certificate':
            raise VaultEnvError('Both a secret ID and a client certificate are set (VAULT_SECRET_ID / VAULT_CLIENT_CERTIFICATE_PATH): '
                                'AppRole login takes one or the other.', 'config')
        if not role_id:
            role_id = _read_secret_file(role_id_file, 'VAULT_ROLE_ID_FILE')
        if auth == 'certificate':
            if password is None and password_file:
                password = _read_password_file(password_file)
        elif not secret_id and secret_id_file:
            secret_id = _read_secret_file(secret_id_file, 'VAULT_SECRET_ID_FILE')
    elif cert_path:
        raise VaultEnvError('VAULT_CLIENT_CERTIFICATE_PATH is set but VAULT_ROLE_ID is not: certificate login needs both.', 'config')
    elif approle_given:
        raise VaultEnvError('VAULT_SECRET_ID is set but VAULT_ROLE_ID is not: AppRole login needs both.', 'config')
    else:
        raise VaultEnvError('No token: set VAULT_TOKEN or VAULT_TOKEN_FILE.', 'config')
    approle_mount = non_empty(pick('approle_mount', 'VAULT_ENV_APPROLE_MOUNT')) or 'approle'
    if not _valid_mount(approle_mount):
        raise VaultEnvError('VAULT_ENV_APPROLE_MOUNT must be a mount path such as approle.', 'config')
    jwt_mount = (non_empty(pick('jwt_mount', 'VAULT_ENV_JWT_MOUNT')) or 'jwt') if auth == 'certificate' else None
    if jwt_mount is not None and not _valid_mount(jwt_mount):
        raise VaultEnvError('VAULT_ENV_JWT_MOUNT must be a mount path such as jwt.', 'config')

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

    return {
        'configured': True,
        'addr': addr.rstrip('/'),
        'insecure_http': url.scheme == 'http' and not is_loopback(url.hostname),
        'auth': auth,
        'token': token if auth == 'token' else None,
        'role_id': role_id if auth != 'token' else None,
        'secret_id': secret_id if auth == 'approle' else None,
        'approle_mount': approle_mount,
        'certificate_path': cert_path if auth == 'certificate' else None,
        'key_path': key_path if auth == 'certificate' else None,
        'certificate_password': password if auth == 'certificate' else None,
        'jwt_mount': jwt_mount,
        'approle_vars_used': used,
        'notes': notes,
        'token_from_file': token_from_file,
        'namespace': non_empty(pick('namespace', 'VAULT_NAMESPACE')),
        'ssl_context': ssl_context(non_empty(pick('cacert', 'VAULT_CACERT')), non_empty(pick('capath', 'VAULT_CAPATH'))),
        'imports': [parse_import(i) for i in imports],
        'base': non_empty(pick('base', 'VAULT_ENV_BASE')),
        'override': flag('override', 'VAULT_ENV_OVERRIDE'),
        'keep_token': keep_token,
        'timeout': num(pick('timeout', 'VAULT_ENV_TIMEOUT'), 10, 'VAULT_ENV_TIMEOUT'),
        'retries': int(num(pick('retries', 'VAULT_ENV_RETRIES'), 3, 'VAULT_ENV_RETRIES')),
        'retry_delay': options['retry_delay'] if options.get('retry_delay') is not None else 1.0,
        'case_insensitive': bool(options['case_insensitive']) if options.get('case_insensitive') is not None else os.name == 'nt',
    }


def enabled_switch(env):
    """VAULT_ENV_ENABLED: None when unset or blank (0.2 behaviour), False to load nothing,
    True to require a configuration. Anything else is a mistake, not a guess."""
    v = non_empty(env.get('VAULT_ENV_ENABLED'))
    if v is None:
        return None
    if v.lower() in FALSY:
        return False
    if v.lower() in TRUTHY:
        return True
    raise VaultEnvError('VAULT_ENV_ENABLED must be true or false (or 1/0, yes/no, on/off).', 'config')


def _read_secret_file(path, name):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            v = f.read().strip()
    except OSError as e:
        raise VaultEnvError('Cannot read %s (%s): %s.' % (name, path, _errno_name(e)), 'config')
    if not v:
        raise VaultEnvError('%s (%s) is empty.' % (name, path), 'config')
    return v


def _read_password_file(path):
    """A password file loses one trailing line break, nothing else: a password may
    begin or end with spaces."""
    try:
        with open(path, 'r', encoding='utf-8', newline='') as f:
            v = f.read()
    except OSError as e:
        raise VaultEnvError('Cannot read VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE (%s): %s.' % (path, _errno_name(e)), 'config')
    v = re.sub(r'\r?\n\Z', '', v)
    if not v:
        raise VaultEnvError('VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE (%s) is empty.' % path, 'config')
    return v


def _valid_mount(m):
    return bool(APPROLE_MOUNT.match(m)) and not any(seg in ('.', '..') for seg in m.split('/'))


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
    def __init__(self, what, sent=True):
        super(_NetworkError, self).__init__(what)
        self.what = what
        # False when the request cannot have reached the server (urllib wraps
        # connect and send failures in URLError); a login is retried only then.
        self.sent = sent


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
    return http_request(cfg, 'GET', api_path)


def http_request(cfg, method, api_path, body=None, with_token=True):
    """One request; `body` is sent as JSON. The AppRole login carries no token."""
    headers = {}
    if with_token:
        headers['X-Vault-Token'] = cfg['token']
    headers.update({
        'X-Vault-Request': 'true',
        'User-Agent': 'vault-env-loader/%s python/%s' % (__version__, '.'.join(map(str, sys.version_info[:3]))),
        'Accept': 'application/json',
    })
    if cfg.get('namespace'):
        headers['X-Vault-Namespace'] = cfg['namespace']
    data = None
    if body is not None:
        data = json.dumps(body).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request('%s/v1/%s' % (cfg['addr'], api_path), data=data, headers=headers, method=method)
    try:
        resp = _opener(cfg).open(req, timeout=cfg['timeout'])
    except urllib.error.HTTPError as e:
        resp = e
    except socket.timeout:
        raise _NetworkError('timed out')
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, socket.timeout):
            raise _NetworkError('timed out', sent=False)
        if isinstance(reason, ssl.SSLError):
            raise _NetworkError('failed (TLS: %s)' % (getattr(reason, 'reason', None) or 'certificate verification failed'), sent=False)
        raise _NetworkError('failed (%s)' % (_errno_name(reason) if isinstance(reason, OSError) else 'network error'), sent=False)
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
# AppRole: log in once, read, revoke the session.

def approle_login(cfg):
    """Retry a login only when Vault cannot have processed it: the request never went
    out, or Vault said so (429, 503). After it went out, a retry could spend another use
    of a limited secret ID and then fail as "invalid"."""
    body = {'role_id': cfg['role_id']}
    if cfg['secret_id']:
        body['secret_id'] = cfg['secret_id']
    api_path = 'auth/%s/login' % cfg['approle_mount']
    attempt = 0
    while True:
        res, net_err = None, None
        try:
            res = http_request(cfg, 'POST', api_path, body, with_token=False)
        except _NetworkError as e:
            net_err = e
        again = res[0] in (429, 503) if res is not None else not net_err.sent
        if not again or attempt >= cfg['retries']:
            if net_err is not None:
                raise VaultEnvError('AppRole login to Vault %s.%s' % (net_err.what, '' if net_err.what == 'timed out' else _proxy_hint(cfg)), 'unavailable')
            break
        time.sleep(cfg['retry_delay'] * (2 ** attempt))
        attempt += 1
    status, resp = res
    if status in (400, 401, 403):
        raise VaultEnvError('AppRole login failed: the role ID or secret ID is invalid, expired or used up (mount %s).' % cfg['approle_mount'], 'auth')
    if status != 200:
        raise VaultEnvError('Vault answered HTTP %s to the AppRole login.' % status, 'unavailable')
    auth = resp.get('auth') if isinstance(resp, dict) else None
    token = auth.get('client_token') if isinstance(auth, dict) else None
    if not isinstance(token, str) or not token:
        raise VaultEnvError('Vault answered the AppRole login without a token (unexpected response).', 'unavailable')
    cfg['token'] = token


def revoke_session(cfg):
    """Best effort: the session expires by itself if this fails."""
    what = 'certificate login session' if cfg.get('auth') == 'certificate' else 'AppRole session'
    try:
        status, _ = http_request(cfg, 'POST', 'auth/token/revoke-self')
        if status not in (200, 204):
            warn('Could not revoke the %s (HTTP %s); it expires by itself.' % (what, status))
    except _NetworkError as e:
        warn('Could not revoke the %s (%s); it expires by itself.' % (what, e.what))
    finally:
        cfg['token'] = None


# ---------------------------------------------------------------------------
# Certificate login: sign a short-lived JWT (a client assertion) with the private
# key, log in with auth/<mount>/login {role, jwt}, read, revoke the session.

PEM_CERT = re.compile(r'-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----')
PEM_KEY = re.compile(r'-----BEGIN ((?:RSA |EC |ENCRYPTED )?PRIVATE KEY)-----[\s\S]+?-----END \1-----')
CERT_NEEDS_CRYPTOGRAPHY = ('Certificate login needs the cryptography package, which is not installed: '
                           'pip install "vault-env-loader[cert]".')


def _crypto():
    """The cryptography modules, imported only when a certificate is used."""
    try:
        # cryptography announces its own deprecations (old Pythons) at import; that is
        # not this run's business, and under -W error it would hide the real result.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    except ImportError:
        raise VaultEnvError(CERT_NEEDS_CRYPTOGRAPHY, 'config')
    return {'x509': x509, 'hashes': hashes, 'serialization': serialization, 'ec': ec, 'padding': padding, 'rsa': rsa, 'utils': utils}


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def load_client_certificate(cert_path, key_path=None, password=None):
    """Read the certificate and its private key. Every problem is a config error, raised
    before any request; messages name files, never their contents."""
    def read(path, what):
        try:
            with open(path, 'r', encoding='latin-1') as f:
                return f.read()
        except OSError as e:
            raise VaultEnvError('Cannot read the client %s file (%s): %s.' % (what, path, _errno_name(e)), 'config')

    cert_text = read(cert_path, 'certificate')
    cm = PEM_CERT.search(cert_text)
    if not cm:
        raise VaultEnvError('The client certificate file (%s) holds no PEM certificate (-----BEGIN CERTIFICATE-----). '
                            'PKCS#12 / PFX is not supported: convert it to PEM.' % cert_path, 'config')
    c = _crypto()
    ser = c['serialization']
    der = base64.b64decode(re.sub(r'\s+', '', cm.group(1)))
    try:
        cert = c['x509'].load_der_x509_certificate(der)
        cert_spki = cert.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
    except Exception:
        raise VaultEnvError('The client certificate file (%s) does not hold a valid X.509 certificate.' % cert_path, 'config')
    key_file = key_path or cert_path
    key_text = read(key_path, 'key') if key_path else cert_text
    km = PEM_KEY.search(key_text)
    if not km:
        if key_path:
            raise VaultEnvError('No private key in the client key file (%s).' % key_path, 'config')
        raise VaultEnvError('No private key in the client certificate file (%s): put the key in the same PEM file, '
                            'or set VAULT_CLIENT_KEY_PATH.' % cert_path, 'config')
    encrypted = km.group(1) == 'ENCRYPTED PRIVATE KEY' or re.search(r'Proc-Type:\s*4,ENCRYPTED', km.group(0)) is not None
    if encrypted and password is None:
        raise VaultEnvError('The private key in %s is encrypted: set VAULT_CLIENT_CERTIFICATE_PASSWORD or '
                            'VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE.' % key_file, 'config')
    try:
        key = ser.load_pem_private_key(km.group(0).encode('latin-1'), password=password.encode('utf-8') if encrypted else None)
    except Exception:
        if encrypted:
            raise VaultEnvError('Cannot decrypt the private key in %s: wrong password.' % key_file, 'config')
        raise VaultEnvError('The private key in %s is not a valid PEM key.' % key_file, 'config')
    hashes, ec = c['hashes'], c['ec']
    if isinstance(key, c['rsa'].RSAPrivateKey):
        alg, curve = 'RS256', None
    elif isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name in ('secp256r1', 'secp384r1'):
        alg, curve = ('ES256', (hashes.SHA256, 32)) if key.curve.name == 'secp256r1' else ('ES384', (hashes.SHA384, 48))
    else:
        raise VaultEnvError('Unsupported key in %s: use RSA or EC P-256 / P-384.' % key_file, 'config')
    if key.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo) != cert_spki:
        raise VaultEnvError('The private key in %s does not belong to the certificate in %s.' % (key_file, cert_path), 'config')
    return {'key': key, 'alg': alg, 'curve': curve, 'x5t': _b64url(hashlib.sha256(der).digest()),
            'not_after': calendar.timegm(not_after.utctimetuple()), '_crypto': c}


def audience(addr, mount):
    """VAULT_ADDR normalised + /v1/auth/<mount>/login: the aud claim."""
    u = urllib.parse.urlsplit(str(addr).strip())
    scheme = u.scheme.lower()
    try:
        port = u.port
    except ValueError:
        port = -1
    if scheme not in ('http', 'https') or not u.hostname or port == -1:
        raise VaultEnvError('VAULT_ADDR is not a valid URL.', 'config')
    host = '[%s]' % u.hostname if ':' in u.hostname else u.hostname
    if port is not None and port != {'https': 443, 'http': 80}[scheme]:
        host += ':%d' % port
    return '%s://%s%s/v1/auth/%s/login' % (scheme, host, re.sub(r'/+$', '', u.path), mount)


def sign_assertion(cred, role_id, aud, now=None):
    """Header, claims and signature. A new iat and jti on every call."""
    iat = int(time.time() if now is None else now)
    header = {'alg': cred['alg'], 'typ': 'JWT', 'x5t#S256': cred['x5t']}
    claims = {'iss': role_id, 'sub': role_id, 'aud': aud, 'iat': iat, 'exp': iat + ASSERTION_LIFETIME,
              'jti': base64.b16encode(os.urandom(16)).decode('ascii').lower()}

    def part(obj):
        return _b64url(json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))

    signing_input = '%s.%s' % (part(header), part(claims))
    data = signing_input.encode('ascii')
    c = cred['_crypto']
    if cred['curve']:
        hash_cls, size = cred['curve']
        r, s = c['utils'].decode_dss_signature(cred['key'].sign(data, c['ec'].ECDSA(hash_cls())))
        sig = r.to_bytes(size, 'big') + s.to_bytes(size, 'big')
    else:
        sig = cred['key'].sign(data, c['padding'].PKCS1v15(), c['hashes'].SHA256())
    return '%s.%s' % (signing_input, _b64url(sig))


def _iso_date(sec):
    return time.strftime('%Y-%m-%d', time.gmtime(sec))


def certificate_status(not_after, now):
    """Days left (rounded down), the warning (below 30 days, or expired) and check's text."""
    days = int((not_after - now) // 86400)
    date = _iso_date(not_after)
    expired = not_after <= now
    warning = None
    if expired:
        warning = 'The client certificate expired on %s.' % date
    elif days < CERT_WARN_DAYS:
        warning = 'The client certificate expires in %d day(s), on %s. Replace it before then.' % (days, date)
    return {'days': days, 'warning': warning, 'text': 'expired %s' % date if expired else 'expires %s, %d days' % (date, days)}


def certificate_check_line(role_id, x5t, status, mount):
    return 'auth     certificate (role_id %s..., cert %s..., %s, mount %s; session revoked after reading)' % (
        str(role_id)[:8], x5t[:8], status['text'], mount)


def client_assertion(role_id=None, certificate_path=None, key_path=None, password=None, vault_addr=None, mount='jwt'):
    """A client assertion for auth/<mount>/login, for Vault clients that cannot sign one
    themselves (hvac: client.auth.jwt.jwt_login(role=role_id, jwt=...)).
    Needs the cryptography package: pip install "vault-env-loader[cert]"."""
    for name, v in (('role_id', role_id), ('certificate_path', certificate_path), ('vault_addr', vault_addr)):
        if not non_empty(v):
            raise VaultEnvError('client_assertion() needs %s.' % name, 'config')
    mount = non_empty(mount) or 'jwt'
    if not _valid_mount(mount):
        raise VaultEnvError('The JWT mount must be a mount path such as jwt.', 'config')
    password = None if password is None or password == '' else str(password)
    cred = load_client_certificate(certificate_path.strip(), non_empty(key_path), password)
    return sign_assertion(cred, role_id.strip(), audience(vault_addr, mount))


def certificate_login(cfg):
    """Unlike a secret ID, a certificate can log in any number of times, so every failure
    that may pass is retried (connection, timeout, 429, 5xx), each time with a new
    assertion. A session the server may have issued expires by itself."""
    api_path = 'auth/%s/login' % cfg['jwt_mount']
    aud = audience(cfg['addr'], cfg['jwt_mount'])
    attempt = 0
    while True:
        res, net_err = None, None
        try:
            body = {'role': cfg['role_id'], 'jwt': sign_assertion(cfg['credential'], cfg['role_id'], aud)}
            res = http_request(cfg, 'POST', api_path, body, with_token=False)
        except _NetworkError as e:
            net_err = e
        again = res[0] == 429 or res[0] >= 500 if res is not None else True
        if not again or attempt >= cfg['retries']:
            if net_err is not None:
                raise VaultEnvError('Certificate login to Vault %s.%s' % (net_err.what, '' if net_err.what == 'timed out' else _proxy_hint(cfg)), 'unavailable')
            break
        time.sleep(cfg['retry_delay'] * (2 ** attempt))
        attempt += 1
    status, resp = res
    if status in (400, 401, 403):
        raise VaultEnvError('Certificate login failed: the role ID or certificate is not accepted (mount %s).' % cfg['jwt_mount'], 'auth')
    if status != 200:
        raise VaultEnvError('Vault answered HTTP %s to the certificate login.' % status, 'unavailable')
    auth = resp.get('auth') if isinstance(resp, dict) else None
    token = auth.get('client_token') if isinstance(auth, dict) else None
    if not isinstance(token, str) or not token:
        raise VaultEnvError('Vault answered the certificate login without a token (unexpected response).', 'unavailable')
    cfg['token'] = token


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
    if cfg.get('auth') not in ('approle', 'certificate'):
        return _collect(cfg)
    if cfg['auth'] == 'certificate':
        # Read and check the files first: a bad certificate fails before any request.
        cfg['credential'] = load_client_certificate(cfg['certificate_path'], cfg['key_path'], cfg['certificate_password'])
        cfg['certificate'] = certificate_status(cfg['credential']['not_after'], time.time())
        certificate_login(cfg)
    else:
        approle_login(cfg)
    try:
        return _collect(cfg)
    finally:
        revoke_session(cfg)


def _collect(cfg):
    warnings = list(cfg.get('notes') or [])
    if cfg['insecure_http']:
        warnings.append('VAULT_ADDR uses plain http: the token and every secret cross the network unencrypted.')
    if cfg.get('certificate') and cfg['certificate']['warning']:
        warnings.append(cfg['certificate']['warning'])
    me = lookup_self(cfg)
    # An AppRole session is short-lived by design: its TTL is no reason to warn.
    if cfg.get('auth') not in ('approle', 'certificate') and me and not me['denied'] and 0 < me['ttl'] < TTL_WARN_SECONDS:
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
    strip_credentials(env, cfg)
    return list(p['set'])


def strip_credentials(env, cfg):
    """After a load, and when VAULT_ENV_ENABLED is off: the application never sees the credentials."""
    if cfg['keep_token']:
        return
    env.pop('VAULT_TOKEN', None)
    if cfg['token_from_file']:
        env.pop('VAULT_TOKEN_FILE', None)
    # Only the AppRole variables this run actually used.
    for name in cfg.get('approle_vars_used') or []:
        env.pop(name, None)


NOT_CONFIGURED = 'VAULT_ADDR and VAULT_ENV_IMPORT are not set; nothing loaded from Vault.'
DISABLED = 'VAULT_ENV_ENABLED is off; nothing loaded from Vault.'
ENABLED_NOT_CONFIGURED = 'VAULT_ENV_ENABLED is on, but VAULT_ADDR and VAULT_ENV_IMPORT are not set.'


def _not_loaded(env, cfg):
    """Nothing to load. Switched off, the credentials still leave the environment;
    VAULT_ENV_LOADED is not set, since nothing was loaded."""
    if cfg.get('disabled'):
        warn(DISABLED)
        strip_credentials(env, cfg)
    else:
        warn(NOT_CONFIGURED)
    return []


# ---------------------------------------------------------------------------
# Library API

def fetch(env=None, **options):
    """Read the configured imports and return {NAME: value} without touching the environment.

    Keyword options mirror the environment variables: addr, token, token_file, role_id,
    role_id_file, secret_id, secret_id_file, approle_mount, client_certificate_path,
    client_key_path, client_certificate_password, client_certificate_password_file, jwt_mount,
    imports, base, namespace, cacert, capath, timeout, retries, allow_http.
    """
    cfg = read_config(options, os.environ if env is None else env)
    if cfg.get('disabled'):
        warn(DISABLED)
        return {}
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
        return _not_loaded(env, cfg)
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

Certificate login needs: pip install "vault-env-loader[cert]"

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
        elif a in ('--addr', '--token-file', '--role-id-file', '--secret-id-file', '--approle-mount', '--client-certificate-path',
                   '--client-key-path', '--jwt-mount', '--import', '--base', '--timeout', '--retries'):
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
        elif a == '--secret-id':
            raise VaultEnvError('There is no --secret-id option: command-line arguments are visible to every user (ps). '
                                'Use VAULT_SECRET_ID or --secret-id-file.', 'config')
        elif a == '--client-certificate-password':
            raise VaultEnvError('There is no --client-certificate-password option: command-line arguments are visible to every '
                                'user (ps). Use VAULT_CLIENT_CERTIFICATE_PASSWORD or VAULT_CLIENT_CERTIFICATE_PASSWORD_FILE.', 'config')
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
        sys.stdout.write((DISABLED if cfg.get('disabled') else NOT_CONFIGURED) + '\n')
        return 0
    result = collect(cfg)
    me = result['self']
    base_info = result['base_info']
    lines = ['vault-env-loader %s' % __version__, 'addr     %s' % cfg['addr']]
    if cfg.get('auth') == 'approle':
        lines.append('auth     approle (role_id %s..., mount %s; session revoked after reading)' % (cfg['role_id'][:8], cfg['approle_mount']))
    if cfg.get('auth') == 'certificate':
        lines.append(certificate_check_line(cfg['role_id'], cfg['credential']['x5t'], cfg['certificate'], cfg['jwt_mount']))
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
            _not_loaded(env, cfg)
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

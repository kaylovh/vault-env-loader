import contextlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..'))
import vault_env_loader as V  # noqa: E402
from fake_vault import FakeVault  # noqa: E402

MODULE = os.path.join(HERE, '..', 'vault_env_loader.py')
TOKEN = 'test-token-123'
BOUND = {'application': 'order-service', 'environment': 'prod'}
FAST = {'retry_delay': 0.001}


def v2(data, version=1):
    return {'status': 200, 'body': {'data': {'data': data, 'metadata': {'version': version}}}}


def me(meta, ttl=0):
    return {'status': 200, 'body': {'data': {'ttl': ttl, 'meta': meta}}}


def mounts(version, path='secret/'):
    return {'status': 200, 'body': {'data': {'path': path, 'type': 'kv', 'options': {'version': str(version)}}}}


def base_env(addr, **extra):
    env = {'VAULT_ADDR': addr, 'VAULT_TOKEN': TOKEN}
    env.update(extra)
    return env


@contextlib.contextmanager
def captured_stderr():
    buf = io.StringIO()
    old = sys.stderr
    sys.stderr = buf
    try:
        yield buf
    finally:
        sys.stderr = old


class Config(unittest.TestCase):
    def test_not_configured_is_a_noop(self):
        with captured_stderr() as err:
            self.assertEqual(V.load(env={}), [])
        self.assertIn('not set; nothing loaded', err.getvalue())

    def test_partial_configuration_fails(self):
        for env in ({'VAULT_ENV_IMPORT': 'db'}, {'VAULT_ADDR': 'https://v.example.com', 'VAULT_ENV_IMPORT': 'db'}):
            with self.assertRaises(V.VaultEnvError) as cm:
                V.load(env=env)
            self.assertEqual(cm.exception.code, 'config')

    def test_skip_verify_is_refused_not_ignored(self):
        env = {'VAULT_ADDR': 'https://v.example.com', 'VAULT_TOKEN': 't', 'VAULT_ENV_IMPORT': 'db'}
        with self.assertRaises(V.VaultEnvError):
            V.read_config({}, dict(env, VAULT_SKIP_VERIFY='true'))
        self.assertTrue(V.read_config({}, dict(env, VAULT_SKIP_VERIFY='false'))['configured'])

    def test_plain_http_only_to_loopback_unless_allowed(self):
        env = {'VAULT_TOKEN': 't', 'VAULT_ENV_IMPORT': 'db'}
        with self.assertRaisesRegex(V.VaultEnvError, 'plain http'):
            V.read_config({}, dict(env, VAULT_ADDR='http://vault.internal:8200'))
        self.assertTrue(V.read_config({}, dict(env, VAULT_ADDR='http://vault.internal:8200', VAULT_ENV_ALLOW_HTTP='true'))['insecure_http'])
        self.assertFalse(V.read_config({}, dict(env, VAULT_ADDR='http://localhost:8200'))['insecure_http'])
        self.assertFalse(V.read_config({}, dict(env, VAULT_ADDR='http://[::1]:8200'))['insecure_http'])

    def test_bad_addr(self):
        env = {'VAULT_TOKEN': 't', 'VAULT_ENV_IMPORT': 'db'}
        for addr in ('vault.example.com', 'ftp://vault.example.com'):
            with self.assertRaises(V.VaultEnvError):
                V.read_config({}, dict(env, VAULT_ADDR=addr))

    def test_token_from_file(self):
        d = tempfile.mkdtemp()
        try:
            f = os.path.join(d, 'token')
            with open(f, 'w') as fh:
                fh.write('  %s\n' % TOKEN)
            cfg = V.read_config({}, {'VAULT_ADDR': 'https://v.example.com', 'VAULT_TOKEN_FILE': f, 'VAULT_ENV_IMPORT': 'db'})
            self.assertEqual(cfg['token'], TOKEN)
            self.assertTrue(cfg['token_from_file'])
        finally:
            shutil.rmtree(d)

    def test_token_flag_is_refused(self):
        with self.assertRaisesRegex(V.VaultEnvError, 'no --token option'):
            V.parse_args(['--token', 'x', '--', 'true'])

    def test_parse_args(self):
        p = V.parse_args(['--import', 'a,b', '--import', 'c', '--override', '--', 'gunicorn', '--workers', '2'])
        self.assertEqual(p['opts']['imports'], ['a', 'b', 'c'])
        self.assertTrue(p['opts']['override'])
        self.assertEqual(p['command'], ['gunicorn', '--workers', '2'])
        self.assertEqual(V.parse_args(['python', 'app.py'])['command'], ['python', 'app.py'])
        self.assertEqual(V.parse_args(['check'])['sub'], 'check')

    def test_non_string_values(self):
        self.assertEqual(V.string_value(1.0), '1')
        self.assertEqual(V.string_value(1.5), '1.5')
        self.assertEqual(V.string_value(False), 'false')
        self.assertEqual(V.string_value(['ä']), '["ä"]')


class Reading(unittest.TestCase):
    def fetch(self, v, **env):
        return V.fetch(env=base_env(v.addr, **env), **FAST)

    def assertCode(self, code, fn, *args, **kwargs):
        with self.assertRaises(V.VaultEnvError) as cm:
            fn(*args, **kwargs)
        self.assertEqual(cm.exception.code, code, cm.exception.message)
        return cm.exception

    def test_relative_imports_names_headers(self):
        with FakeVault({
            'auth/token/lookup-self': me(BOUND),
            'sys/internal/ui/mounts/secret/order-service/prod/database': mounts(2),
            'secret/data/order-service/prod/database': v2({'db.password': 's3cr3t', 'DB_USER': 'app'}, 7),
            'sys/internal/ui/mounts/secret/order-service/prod': mounts(2),
            'secret/data/order-service/prod': v2({'DEFAULT_ONE': 'd'}),
        }, token=TOKEN) as v:
            env = base_env(v.addr, VAULT_ENV_IMPORT='database, vault://')
            names = V.load(env=env, **FAST)
            self.assertEqual(sorted(names), ['DB_PASSWORD', 'DB_USER', 'DEFAULT_ONE'])
            self.assertEqual(env['DB_PASSWORD'], 's3cr3t')
            self.assertEqual(env['VAULT_ENV_LOADED'], '1')
            self.assertNotIn('VAULT_TOKEN', env)
            self.assertTrue(all(r['token'] == TOKEN for r in v.requests))
            self.assertRegex(v.requests[0]['ua'], r'^vault-env-loader/\d+\.\d+\.\d+ python/\d+\.\d+')
            # Already loaded: a second call does nothing.
            n = len(v.requests)
            self.assertEqual(V.load(env=env, **FAST), [])
            self.assertEqual(len(v.requests), n)

    def test_kv1_detected(self):
        with FakeVault({
            'auth/token/lookup-self': me(BOUND),
            'sys/internal/ui/mounts/secret/order-service/prod/legacy': mounts(1),
            'secret/order-service/prod/legacy': {'status': 200, 'body': {'data': {'A': '1'}}},
        }, token=TOKEN) as v:
            self.assertEqual(self.fetch(v, VAULT_ENV_IMPORT='legacy'), {'A': '1'})

    def test_explicit_kv_skips_probe(self):
        with FakeVault({'auth/token/lookup-self': me(BOUND),
                        'secret/order-service/prod/legacy': {'status': 200, 'body': {'data': {'A': '1'}}}}, token=TOKEN) as v:
            self.fetch(v, VAULT_ENV_IMPORT='legacy?kv=1')
            self.assertFalse(any(p.startswith('sys/internal') for p in v.paths()))

    def test_absolute_path_for_other_binding_fails_locally(self):
        with FakeVault({'auth/token/lookup-self': me(BOUND)}, token=TOKEN) as v:
            self.assertCode('config', self.fetch, v, VAULT_ENV_IMPORT='vault://secret/order-service/dev/database')
            self.assertEqual(v.paths(), ['auth/token/lookup-self'])

    def test_lookup_self_denied(self):
        with FakeVault({
            'auth/token/lookup-self': {'status': 403, 'body': {'errors': ['permission denied']}},
            'sys/internal/ui/mounts/kv/team/app': mounts(2, 'kv/'),
            'kv/data/team/app': v2({'X': 'y'}),
        }, token=TOKEN) as v:
            self.assertEqual(self.fetch(v, VAULT_ENV_IMPORT='vault://kv/team/app'), {'X': 'y'})
            self.assertCode('auth', self.fetch, v, VAULT_ENV_IMPORT='app')

    def test_base_wins_over_metadata(self):
        with FakeVault({'auth/token/lookup-self': me(BOUND), 'kv/data/x/y/z': v2({'Q': '1'})}, token=TOKEN) as v:
            self.assertEqual(self.fetch(v, VAULT_ENV_IMPORT='z?kv=2', VAULT_ENV_BASE='kv/x/y'), {'Q': '1'})

    def test_wrong_token_not_retried(self):
        with FakeVault({'secret/data/a/b': v2({'A': '1'})}, token=TOKEN) as v:
            self.assertCode('auth', self.fetch, v, VAULT_TOKEN='wrong', VAULT_ENV_IMPORT='vault://secret/a/b?kv=2')
            self.assertEqual(v.paths().count('secret/data/a/b'), 1)

    def test_503_then_200(self):
        with FakeVault({'secret/data/a/b': [{'status': 503, 'body': {'errors': ['sealed']}}, v2({'A': '1'})]}) as v:
            self.assertEqual(self.fetch(v, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2'), {'A': '1'})

    def test_retries_are_bounded(self):
        with FakeVault({'secret/data/a/b': {'status': 503, 'body': {'errors': []}}}) as v:
            self.assertCode('unavailable', self.fetch, v, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2', VAULT_ENV_RETRIES='2')
            self.assertEqual(v.paths().count('secret/data/a/b'), 3)

    def test_502_reasons(self):
        def unresolved(reason):
            return {'status': 502, 'body': {'errors': ["alias 'password' could not be resolved: %s" % reason]}}
        with FakeVault({'secret/data/a/t': [unresolved('timeout'), v2({'A': '1'})],
                        'secret/data/a/p': unresolved('grant_revoked')}) as v:
            self.assertEqual(self.fetch(v, VAULT_ENV_IMPORT='vault://secret/a/t?kv=2'), {'A': '1'})
            e = self.assertCode('resolve', self.fetch, v, VAULT_ENV_IMPORT='vault://secret/a/p?kv=2')
            self.assertIn('password (grant_revoked)', e.message)
            self.assertEqual(v.paths().count('secret/data/a/p'), 1)

    def test_timeouts_are_retried(self):
        with FakeVault({'secret/data/a/b': [{'hang': True}, v2({'A': '1'})]}) as v:
            self.assertEqual(self.fetch(v, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2', VAULT_ENV_TIMEOUT='0.3'), {'A': '1'})

    def test_connection_refused(self):
        v = FakeVault({})
        addr = v.addr
        v.close()
        with self.assertRaises(V.VaultEnvError) as cm:
            V.fetch(env={'VAULT_ADDR': addr, 'VAULT_TOKEN': TOKEN, 'VAULT_ENV_IMPORT': 'vault://secret/a/b?kv=2',
                         'VAULT_ENV_RETRIES': '1'}, **FAST)
        self.assertEqual(cm.exception.code, 'unavailable')
        self.assertNotIn(TOKEN, cm.exception.message)

    def test_redirects_are_not_followed(self):
        with FakeVault({'secret/data/a/b': v2({'A': '1'})}) as other:
            with FakeVault({'secret/data/a/b': {'redirect': other.addr + '/v1/secret/data/a/b'}}) as v:
                self.assertCode('unavailable', self.fetch, v, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2')
            self.assertEqual(other.requests, [], 'the token must not follow a redirect')

    def test_optional_only_skips_missing(self):
        with FakeVault({'secret/data/a/b': v2({'A': '1'}),
                        'secret/data/a/denied': {'status': 403, 'body': {'errors': ['permission denied']}}}) as v:
            self.assertEqual(self.fetch(v, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2, optional:vault://secret/a/missing?kv=2'), {'A': '1'})
            self.assertCode('not_found', self.fetch, v, VAULT_ENV_IMPORT='vault://secret/a/missing?kv=2')
            self.assertCode('auth', self.fetch, v, VAULT_ENV_IMPORT='optional:vault://secret/a/denied?kv=2')

    def test_deleted_latest_version_is_missing(self):
        with FakeVault({'secret/data/a/b': {'status': 200, 'body': {'data': {'data': None, 'metadata': {'version': 3}}}}}) as v:
            self.assertCode('not_found', self.fetch, v, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2')

    def test_existing_variables_win_unless_override(self):
        with FakeVault({'secret/data/a/b': v2({'A': 'from-vault', 'B': 'from-vault'})}) as v:
            env = base_env(v.addr, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2', A='local')
            with captured_stderr() as err:
                V.load(env=env, **FAST)
            self.assertEqual(env['A'], 'local')
            self.assertEqual(env['B'], 'from-vault')
            self.assertRegex(err.getvalue(), r'kept as is.*: A\.')
            self.assertNotIn('from-vault', err.getvalue())

            env2 = base_env(v.addr, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2', VAULT_ENV_OVERRIDE='true', A='local')
            V.load(env=env2, **FAST)
            self.assertEqual(env2['A'], 'from-vault')

    def test_short_lived_token_warns(self):
        with FakeVault({'auth/token/lookup-self': me(BOUND, 3 * 86400), 'secret/data/a/b': v2({'A': '1'})}) as soon, \
                FakeVault({'auth/token/lookup-self': me(BOUND, 0), 'secret/data/a/b': v2({'A': '1'})}) as never:
            with captured_stderr() as err:
                V.fetch(env=base_env(soon.addr, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2'), base='secret/a', **FAST)
            self.assertIn('expires in 3 day', err.getvalue())
            with captured_stderr() as err:
                V.fetch(env=base_env(never.addr, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2'), base='secret/a', **FAST)
            self.assertNotIn('expires', err.getvalue())

    def test_values_over_128kb(self):
        with FakeVault({'secret/data/a/b': v2({'BIG': 'x' * (130 * 1024)})}) as v:
            e = self.assertCode('value', self.fetch, v, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2')
            self.assertIn('"BIG"', e.message)

    def test_namespace_header(self):
        with FakeVault({'secret/data/a/b': v2({'A': '1'})}) as v:
            self.fetch(v, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2', VAULT_NAMESPACE='team-a')
            self.assertTrue(all(r['ns'] == 'team-a' for r in v.requests))

    def test_load_writes_os_environ_by_default(self):
        with FakeVault({'secret/data/a/b': v2({'VEL_TEST_ONLY': '1'})}) as v:
            saved = dict(os.environ)
            try:
                os.environ.pop('VAULT_ENV_LOADED', None)
                os.environ.update(base_env(v.addr, VAULT_ENV_IMPORT='vault://secret/a/b?kv=2'))
                self.assertEqual(V.load(**FAST), ['VEL_TEST_ONLY'])
                self.assertEqual(os.environ['VEL_TEST_ONLY'], '1')
                self.assertNotIn('VAULT_TOKEN', os.environ)
            finally:
                os.environ.clear()
                os.environ.update(saved)


# ---------------------------------------------------------------------------
# processes: the wrapper and python -m

PRINT_ENV = ('import json, os; print(json.dumps({"p": os.environ.get("DB_PASSWORD"), '
             '"t": os.environ.get("VAULT_TOKEN"), "l": os.environ.get("VAULT_ENV_LOADED")}))')

ROUTES = {
    'auth/token/lookup-self': me(BOUND),
    'sys/internal/ui/mounts/secret/order-service/prod/database': mounts(2),
    'secret/data/order-service/prod/database': v2({'db.password': 's3cr3t'}),
}


def child_env(addr, **extra):
    env = dict(os.environ)
    for k in ('DB_PASSWORD', 'VAULT_ENV_LOADED', 'VAULT_TOKEN_FILE', 'VAULT_ENV_BASE'):
        env.pop(k, None)
    env.update({'VAULT_ADDR': addr, 'VAULT_TOKEN': TOKEN, 'VAULT_ENV_IMPORT': 'database', 'VAULT_ENV_RETRIES': '0'})
    env.update(extra)
    return env


def run(args, env, timeout=30):
    p = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(timeout=timeout)
    return p.returncode, out.decode(), err.decode()


class Processes(unittest.TestCase):
    def test_wrapper_injects_and_strips_token(self):
        with FakeVault(ROUTES, token=TOKEN) as v:
            code, out, err = run([sys.executable, MODULE, '--', sys.executable, '-c', PRINT_ENV + '; raise SystemExit(3)'], child_env(v.addr))
            self.assertEqual(code, 3, err)
            self.assertEqual(json.loads(out), {'p': 's3cr3t', 't': None, 'l': '1'})

    def test_python_dash_m(self):
        with FakeVault(ROUTES, token=TOKEN) as v:
            env = child_env(v.addr, PYTHONPATH=os.path.join(HERE, '..'))
            code, out, err = run([sys.executable, '-m', 'vault_env_loader', '--', sys.executable, '-c', PRINT_ENV], env)
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out)['p'], 's3cr3t')

    def test_load_from_entry_file(self):
        with FakeVault(ROUTES, token=TOKEN) as v:
            env = child_env(v.addr, PYTHONPATH=os.path.join(HERE, '..'))
            code, out, err = run([sys.executable, '-c', 'import vault_env_loader; vault_env_loader.load(); ' + PRINT_ENV], env)
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out), {'p': 's3cr3t', 't': None, 'l': '1'})

    def test_failure_never_runs_the_command(self):
        with FakeVault(ROUTES, token=TOKEN) as v:
            code, out, err = run([sys.executable, MODULE, '--', sys.executable, '-c', 'print("RAN")'], child_env(v.addr, VAULT_TOKEN='wrong'))
            self.assertEqual(code, 78)
            self.assertNotIn('RAN', out)
            self.assertEqual(len(err.strip().splitlines()), 1, err)
            self.assertNotIn('wrong', err)

    def test_not_configured_runs_anyway(self):
        env = dict(os.environ)
        for k in ('VAULT_ADDR', 'VAULT_ENV_IMPORT', 'VAULT_ENV_LOADED'):
            env.pop(k, None)
        code, out, err = run([sys.executable, MODULE, '--', sys.executable, '-c', 'print("RAN")'], env)
        self.assertEqual(code, 0)
        self.assertIn('RAN', out)
        self.assertIn('nothing loaded', err)

    def test_command_not_found_is_127(self):
        with FakeVault(ROUTES, token=TOKEN) as v:
            code, _, err = run([sys.executable, MODULE, '--', 'vel-no-such-command-xyz'], child_env(v.addr))
            self.assertEqual(code, 127, err)

    def test_check_prints_names_never_values(self):
        with FakeVault(ROUTES, token=TOKEN) as v:
            code, out, err = run([sys.executable, MODULE, 'check'], child_env(v.addr))
            self.assertEqual(code, 0, err)
            self.assertIn('DB_PASSWORD', out)
            self.assertIn('from db.password', out)
            self.assertIn('6 chars', out)
            self.assertNotIn('s3cr3t', out + err)
            self.assertNotIn(TOKEN, out + err)

    def test_version(self):
        code, out, _ = run([sys.executable, MODULE, '--version'], dict(os.environ))
        self.assertEqual((code, out.strip()), (0, V.__version__))

    @unittest.skipIf(os.name == 'nt', 'POSIX exec')
    def test_exec_keeps_the_pid_and_signals_reach_the_command(self):
        with FakeVault(ROUTES, token=TOKEN) as v:
            script = ('import os, signal, sys, time\n'
                      'signal.signal(signal.SIGTERM, lambda *a: sys.exit(42))\n'
                      'print(os.getpid(), flush=True)\n'
                      'time.sleep(30)\n')
            p = subprocess.Popen([sys.executable, MODULE, '--', sys.executable, '-c', script],
                                 env=child_env(v.addr), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            pid = int(p.stdout.readline())
            self.assertEqual(pid, p.pid, 'the wrapper replaced itself with the command')
            time.sleep(0.2)
            p.send_signal(signal.SIGTERM)
            p.communicate(timeout=10)
            self.assertEqual(p.returncode, 42)


# ---------------------------------------------------------------------------
# AppRole (0.2)

ROLE = {'role_id': 'role-123', 'secret_id': 'secret-456'}
APPROLE_ROUTES = dict(ROUTES, **{'auth/token/revoke-self': {'status': 204}})


def role_env(addr, **extra):
    env = {'VAULT_ADDR': addr, 'VAULT_ROLE_ID': ROLE['role_id'], 'VAULT_SECRET_ID': ROLE['secret_id'], 'VAULT_ENV_IMPORT': 'database'}
    env.update(extra)
    return env


def role_child_env(addr, **extra):
    env = child_env(addr, VAULT_ROLE_ID=ROLE['role_id'], VAULT_SECRET_ID=ROLE['secret_id'], **extra)
    env.pop('VAULT_TOKEN', None)
    return env


class AppRole(unittest.TestCase):
    def test_login_read_revoke(self):
        with FakeVault(APPROLE_ROUTES, token=TOKEN, approle=ROLE) as v:
            env = role_env(v.addr)
            with captured_stderr() as err:
                self.assertEqual(V.load(env=env, **FAST), ['DB_PASSWORD'])
            self.assertEqual(env['DB_PASSWORD'], 's3cr3t')
            self.assertNotIn('VAULT_ROLE_ID', env)
            self.assertNotIn('VAULT_SECRET_ID', env)
            self.assertNotIn('expires in', err.getvalue(), 'a short session TTL is not worth a warning')
            self.assertEqual(['%s %s' % (r['method'], r['path']) for r in v.requests], [
                'POST auth/approle/login',
                'GET auth/token/lookup-self',
                'GET sys/internal/ui/mounts/secret/order-service/prod/database',
                'GET secret/data/order-service/prod/database',
                'POST auth/token/revoke-self',
            ])
            self.assertIsNone(v.requests[0]['token'])
            self.assertEqual(v.requests[0]['body'], {'role_id': 'role-123', 'secret_id': '***'})
            self.assertTrue(all(r['token'] == TOKEN for r in v.requests[1:]))

    def test_wrong_secret_id_fails_once_without_reads(self):
        with FakeVault(APPROLE_ROUTES, token=TOKEN, approle=ROLE) as v:
            with self.assertRaises(V.VaultEnvError) as cm:
                V.load(env=role_env(v.addr, VAULT_SECRET_ID='wrong'), **FAST)
            self.assertEqual(cm.exception.code, 'auth')
            self.assertEqual(v.paths(), ['auth/approle/login'])

    def test_session_revoked_even_when_a_read_fails(self):
        with FakeVault(APPROLE_ROUTES, token=TOKEN, approle=ROLE) as v:
            with self.assertRaises(V.VaultEnvError) as cm:
                V.load(env=role_env(v.addr, VAULT_ENV_IMPORT='missing'), **FAST)
            self.assertEqual(cm.exception.code, 'not_found')
            self.assertEqual(v.paths()[-1], 'auth/token/revoke-self')

    def test_failed_revoke_only_warns(self):
        routes = dict(APPROLE_ROUTES, **{'auth/token/revoke-self': {'status': 500, 'body': {'errors': []}}})
        with FakeVault(routes, token=TOKEN, approle=ROLE) as v:
            env = role_env(v.addr)
            with captured_stderr() as err:
                V.load(env=env, **FAST)
            self.assertEqual(env['DB_PASSWORD'], 's3cr3t')
            self.assertIn('Could not revoke the AppRole session (HTTP 500); it expires by itself', err.getvalue())

    def test_token_wins_and_approle_variables_are_left(self):
        with FakeVault(ROUTES, token=TOKEN) as v:
            env = base_env(v.addr, VAULT_ENV_IMPORT='database', VAULT_ROLE_ID='r', VAULT_SECRET_ID='s')
            with captured_stderr() as err:
                V.load(env=env, **FAST)
            self.assertEqual((env['DB_PASSWORD'], env['VAULT_ROLE_ID'], env['VAULT_SECRET_ID']), ('s3cr3t', 'r', 's'))
            self.assertIn('VAULT_TOKEN is set, so VAULT_ROLE_ID / VAULT_SECRET_ID are ignored', err.getvalue())
            self.assertFalse(any(p.endswith('/login') for p in v.paths()))

    def test_login_retried_on_503_not_after_500_or_once_sent(self):
        ok = {'status': 200, 'body': {'auth': {'client_token': TOKEN}}}
        with FakeVault(dict(APPROLE_ROUTES, **{'auth/approle/login': [{'status': 503, 'body': {'errors': []}}, ok]}), token=TOKEN) as v:
            env = role_env(v.addr)
            V.load(env=env, **FAST)
            self.assertEqual(env['DB_PASSWORD'], 's3cr3t')
        with FakeVault(dict(APPROLE_ROUTES, **{'auth/approle/login': {'status': 500, 'body': {'errors': []}}}), token=TOKEN) as v:
            with self.assertRaises(V.VaultEnvError) as cm:
                V.load(env=role_env(v.addr), **FAST)
            self.assertEqual(cm.exception.code, 'unavailable')
            self.assertEqual(len(v.requests), 1)
        with FakeVault(dict(APPROLE_ROUTES, **{'auth/approle/login': {'hang': True}}), token=TOKEN) as v:
            with self.assertRaises(V.VaultEnvError) as cm:
                V.load(env=role_env(v.addr, VAULT_ENV_TIMEOUT='0.3'), **FAST)
            self.assertEqual(cm.exception.code, 'unavailable')
            self.assertEqual(len(v.requests), 1, 'a login the server may have processed is not repeated')

    def test_refused_connection_is_retried(self):
        import socket as _socket
        s = _socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        started = time.time()
        with self.assertRaises(V.VaultEnvError) as cm:
            V.load(env=role_env('http://127.0.0.1:%d' % port, VAULT_ENV_RETRIES='2'), retry_delay=0.05)
        self.assertEqual(cm.exception.code, 'unavailable')
        self.assertGreaterEqual(time.time() - started, 0.14, 'two retries with 50 ms and 100 ms backoff')

    def test_wrapper_strips_used_variables_and_keeps_the_rest(self):
        d = tempfile.mkdtemp()
        try:
            f = os.path.join(d, 'unused-role-id')
            with open(f, 'w') as fh:
                fh.write('other')
            with FakeVault(APPROLE_ROUTES, token=TOKEN, approle=ROLE) as v:
                code, out, err = run([sys.executable, MODULE, '--', sys.executable, '-c',
                                      'import json, os; print(json.dumps({k: os.environ.get(k) for k in '
                                      '("DB_PASSWORD", "VAULT_ROLE_ID", "VAULT_SECRET_ID", "VAULT_ROLE_ID_FILE", "VAULT_TOKEN")}))'],
                                     role_child_env(v.addr, VAULT_ROLE_ID_FILE=f))
                self.assertEqual(code, 0, err)
                self.assertEqual(json.loads(out), {'DB_PASSWORD': 's3cr3t', 'VAULT_ROLE_ID': None, 'VAULT_SECRET_ID': None,
                                                   'VAULT_ROLE_ID_FILE': f, 'VAULT_TOKEN': None})
                self.assertEqual(v.paths()[-1], 'auth/token/revoke-self', 'revoked before exec')
        finally:
            shutil.rmtree(d)

    def test_secret_id_flag_is_refused(self):
        code, _, err = run([sys.executable, MODULE, '--secret-id', 'x', '--', 'true'], dict(os.environ))
        self.assertEqual(code, 78)
        self.assertIn('no --secret-id option', err)

    def test_check_names_the_auth_method_and_revokes(self):
        with FakeVault(APPROLE_ROUTES, token=TOKEN, approle=ROLE) as v:
            code, out, err = run([sys.executable, MODULE, 'check'], role_child_env(v.addr))
            self.assertEqual(code, 0, err)
            self.assertIn('auth     approle (role_id role-123..., mount approle; session revoked after reading)', out)
            self.assertNotIn('secret-456', out + err)
            self.assertEqual(v.paths()[-1], 'auth/token/revoke-self')

    def test_another_mount(self):
        with FakeVault(APPROLE_ROUTES, token=TOKEN, approle=dict(ROLE, mount='ci/approle')) as v:
            env = role_env(v.addr, VAULT_ENV_APPROLE_MOUNT='ci/approle')
            V.load(env=env, **FAST)
            self.assertEqual(env['DB_PASSWORD'], 's3cr3t')
            self.assertEqual(v.paths()[0], 'auth/ci/approle/login')


if __name__ == '__main__':
    unittest.main()

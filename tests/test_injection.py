"""End-to-end tests: run setenv.py/entrypoint.sh against a fake Vault and inspect what reaches GITHUB_ENV/GITHUB_OUTPUT.

Run with: python3 -m unittest discover -s tests -v
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class FakeVault(BaseHTTPRequestHandler):
    setenv_data = {}
    error_body = None

    def log_message(self, *a):
        pass

    def _send(self, body):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = self.path
        if p == '/ip':
            data = b'203.0.113.7\n'
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif p.endswith('/role-id'):
            self._send({'data': {'role_id': 'role-id-1'}})
        elif p.endswith('/setenv'):
            self._send({'data': type(self).setenv_data})
        else:
            self.send_error(404)

    def do_PUT(self):
        if self.error_body:
            data = self.error_body.encode()
            self.send_response(403)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.rfile.read(int(self.headers.get('Content-Length') or 0))
        if self.path.endswith('/secret-id'):
            self._send({'wrap_info': {'token': 'wrap'}})
        elif self.path.endswith('/unwrap'):
            self._send({'data': {'secret_id': 'secret-id-1'}})
        else:
            self.send_error(404)

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length') or 0))
        self._send({'auth': {'client_token': 'tok'}})


def parse_file_commands(text):
    """Parse GITHUB_ENV/GITHUB_OUTPUT the way the runner does (name=value or name<<DELIM blocks)."""
    result, lines, i = {}, text.split('\n'), 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line:
            continue
        if '<<' in line and ('=' not in line or line.index('<<') < line.index('=')):
            name, delim = line.split('<<', 1)
            value = []
            while lines[i] != delim:
                value.append(lines[i])
                i += 1
            i += 1
            result[name] = '\n'.join(value)
        else:
            name, value = line.split('=', 1)
            result[name] = value
    return result


class SetenvInjectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('127.0.0.1', 0), FakeVault)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def run_action(self, secrets_data, **extra_env):
        FakeVault.setenv_data = secrets_data
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        t = Path(tmp.name)
        env_file, out_file = t / 'env', t / 'out'
        env_file.touch()
        out_file.touch()
        env = {
            'PATH': os.environ['PATH'],
            'HOME': str(t),
            'GITHUB_ACTIONS': 'true',
            'GITHUB_ENV': str(env_file),
            'GITHUB_OUTPUT': str(out_file),
            'VAULT_ADDR': f'http://127.0.0.1:{self.port}',
            'INPUT_NAME': 'app',
            'INPUT_ENV': 'prod',
            'INPUT_TOKEN': 'github-token',
            'INPUT_SECRET': 'true',
            'INPUT_EVAL': 'true',
            'INPUT_CACHE_FILE': str(t / 'cache.json'),
            'INPUT_MYIP_URL': f'http://127.0.0.1:{self.port}/ip',
        }
        env.update(extra_env)
        cmd = [sys.executable, str(ROOT / 'setenv.py')]
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=t, timeout=60)
        return proc, parse_file_commands(env_file.read_text()), parse_file_commands(out_file.read_text()), t

    def assert_value_intact(self, value, key='MY_SECRET'):
        marker_dir = tempfile.TemporaryDirectory()
        self.addCleanup(marker_dir.cleanup)
        proc, env, out, t = self.run_action({key: value})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(env[key], value)
        self.assertEqual(out[key], value)
        self.assertNotIn('BASH_ENV', env)
        return proc, t

    def test_command_substitution_is_not_executed(self):
        marker = Path(tempfile.gettempdir()) / f'pwned-subst-{os.getpid()}'
        marker.unlink(missing_ok=True)
        self.addCleanup(lambda: marker.unlink(missing_ok=True))
        self.assert_value_intact(f'$(touch {marker})')
        self.assertFalse(marker.exists(), 'command substitution executed')

    def test_backticks_are_not_executed(self):
        marker = Path(tempfile.gettempdir()) / f'pwned-tick-{os.getpid()}'
        marker.unlink(missing_ok=True)
        self.addCleanup(lambda: marker.unlink(missing_ok=True))
        self.assert_value_intact(f'`touch {marker}`')
        self.assertFalse(marker.exists(), 'backticks executed')

    def test_quotes_survive(self):
        self.assert_value_intact('a"b\'c"; touch /tmp/never "$HOME" \\')

    def test_dollar_expansion_is_not_performed(self):
        self.assert_value_intact('${HOME}-$PATH-$((1+1))')

    def test_newline_cannot_inject_variables(self):
        evil = 'harmless\nBASH_ENV=/tmp/evil.sh\nNODE_OPTIONS=--require /tmp/x'
        _, env, out, _ = self.run_action({'MY_SECRET': evil})[0:4]
        for result in (env, out):
            self.assertEqual(set(result), {'TF_VAR_vault_role_id', 'TF_VAR_vault_secret_id', 'MY_SECRET'})
            self.assertEqual(result['MY_SECRET'], evil)

    def test_value_containing_fake_delimiter_stays_one_value(self):
        self.assert_value_intact('x\nghadelim_deadbeef\nBASH_ENV=/tmp/evil.sh')

    def test_every_line_of_multiline_value_is_masked(self):
        proc, _ = self.assert_value_intact('line-one-secret\nline-two-secret')
        self.assertIn('::add-mask::line-one-secret', proc.stdout)
        self.assertIn('::add-mask::line-two-secret', proc.stdout)

    def test_stdout_contains_only_mask_commands(self):
        proc, _ = self.assert_value_intact('hello\nBASH_ENV=x')
        for line in proc.stdout.splitlines():
            self.assertTrue(line.startswith('::add-mask::'), line)

    def test_secret_key_named_bash_env_is_refused(self):
        proc, env, out, _ = self.run_action({'BASH_ENV': '/tmp/evil.sh'})
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn('BASH_ENV', env)
        self.assertNotIn('BASH_ENV', out)
        self.assertNotIn('/tmp/evil.sh', proc.stdout + proc.stderr)

    DENIED_NAMES = [
        'NODE_OPTIONS', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'PATH', 'GITHUB_PATH', 'RUNNER_TEMP',
        'ACTIONS_RUNTIME_TOKEN', 'ENV', 'BASH_FUNC_x%%', 'IFS', 'SHELL', 'HOME', 'PS4', 'PROMPT_COMMAND',
        'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_PARAMETERS', 'GIT_SSH_COMMAND',
        'GIT_EXEC_PATH', 'GIT_ASKPASS', 'GIT_EXTERNAL_DIFF',
        'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
        'PERL5OPT', 'PERL5LIB', 'RUBYOPT', 'RUBYLIB', 'PYTHONPATH', 'PYTHONSTARTUP', 'NODE_EXTRA_CA_CERTS', 'NODE_PATH',
        'LESSOPEN', 'GCONV_PATH',
        'HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'NO_PROXY',
        'SSL_CERT_FILE', 'SSL_CERT_DIR', 'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE',
        'TF_CLI_ARGS', 'TF_CLI_ARGS_plan', 'TF_CLI_CONFIG_FILE', 'KUBECONFIG',
        'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'NPM_CONFIG_REGISTRY', 'npm_config_registry',
    ]
    INVALID_NAMES = ['', 'A=B', 'X\nBASH_ENV', 'X\rY', 'a<<b']
    ACCEPTED_NAMES = ['my-key', 'my.key', 'lower_case', 'bash_env', 'a b', '1ABC', 'TF_VAR_x', 'ARM_CLIENT_ID',
                      'KUBE_CONFIG_PATH', 'TF_TOKEN_terraform__registry_nrk_cloud', 'GITLAB_TOKEN']

    def test_reserved_and_invalid_key_names_are_refused(self):
        for key in self.DENIED_NAMES + self.INVALID_NAMES:
            with self.subTest(key=key):
                proc, env, out, _ = self.run_action({key: 'v'})
                self.assertNotEqual(proc.returncode, 0)
                self.assertEqual((env, out), ({}, {}))
                self.assertNotIn("'v'", proc.stdout)

    def test_legitimate_key_names_are_accepted(self):
        for key in self.ACCEPTED_NAMES:
            with self.subTest(key=key):
                proc, env, out, _ = self.run_action({key: 'v1'})
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(env[key], 'v1')
                self.assertEqual(out[key], 'v1')

    def test_azure_requires_tenant_subscription_and_resource_group(self):
        for rg in ['', ' ']:
            with self.subTest(resource_group=rg):
                proc, env, out, _ = self.run_action({}, INPUT_AZURE='true', INPUT_AZURE_TENANT_ID='t',
                                                    INPUT_AZURE_SUBSCRIPTION_ID='s', INPUT_AZURE_RESOURCE_GROUP=rg)
                self.assertEqual(proc.returncode, 1)
                self.assertIn('--azure-resource-group', proc.stderr)
                self.assertNotIn('Traceback', proc.stderr)
                self.assertEqual((env, out), ({}, {}))

    def test_vault_error_body_is_not_logged(self):
        FakeVault.error_body = 'SECRET-ERROR-BODY'
        self.addCleanup(setattr, FakeVault, 'error_body', None)
        proc, env, out, _ = self.run_action({})
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn('SECRET-ERROR-BODY', proc.stdout + proc.stderr)

    def test_normal_variables_keep_documented_contract(self):
        proc, env, out, _ = self.run_action({'TF_VAR_x': 'plain'})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        expected = {'TF_VAR_vault_role_id': 'role-id-1', 'TF_VAR_vault_secret_id': 'secret-id-1', 'TF_VAR_x': 'plain'}
        self.assertEqual(env, expected)
        self.assertEqual(out, expected)

    def test_without_eval_nothing_is_exported_and_nothing_leaks(self):
        proc, env, out, _ = self.run_action({'MY_SECRET': 'topsecret$(id)'}, INPUT_EVAL='false')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((env, out), ({}, {}))
        for line in proc.stdout.splitlines():
            self.assertTrue(line.startswith('::add-mask::'), line)

    def test_cached_credentials_are_validated_too(self):
        # A tampered cache file must not be able to inject names or newlines either.
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / 'cache.json'
            cache.write_text(json.dumps({'timestamp': __import__('datetime').datetime.now().isoformat(),
                                         'env_vars': [['BASH_ENV', '/tmp/evil.sh']]}))
            proc, env, out, _ = self.run_action({}, INPUT_CACHE='true', INPUT_CACHE_FILE=str(cache))
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual((env, out), ({}, {}))

    def test_shell_output_mode_quotes_values(self):
        # Outside GitHub Actions the output is shell for a human; it must be safe to eval.
        marker = Path(tempfile.gettempdir()) / f'pwned-shell-{os.getpid()}'
        marker.unlink(missing_ok=True)
        self.addCleanup(lambda: marker.unlink(missing_ok=True))
        value = f"a'$(touch {marker})`id`\nBASH_ENV=1"
        proc, _, _, t = self.run_action({'MY_SECRET': value},
                                        GITHUB_ACTIONS='', INPUT_EVAL='true', INPUT_NEW_LINE='true')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        check = subprocess.run(['bash', '-c', f'eval "$({sys.executable} {ROOT}/setenv.py)"; printf %s "$MY_SECRET"'],
                               env={**os.environ, 'HOME': str(t), 'VAULT_ADDR': f'http://127.0.0.1:{self.port}',
                                    'INPUT_NAME': 'app', 'INPUT_ENV': 'prod', 'INPUT_TOKEN': 't', 'INPUT_SECRET': 'true',
                                    'INPUT_EVAL': 'true', 'INPUT_CACHE_FILE': str(t / 'c'), 'INPUT_MYIP_URL': f'http://127.0.0.1:{self.port}/ip',
                                    'GITHUB_ACTIONS': ''},
                               capture_output=True, text=True, cwd=t)
        self.assertEqual(check.stdout, value)
        self.assertFalse(marker.exists())

    def test_dockerfile_needs_only_the_pinned_base_image(self):
        text = (ROOT / 'Dockerfile').read_text()
        self.assertIn('@sha256:', text.splitlines()[0])
        self.assertNotIn('apk', text)
        self.assertIn('ENTRYPOINT ["python3", "/setenv.py"]', text)
        self.assertFalse((ROOT / 'entrypoint.sh').exists())

    def test_non_identifier_names_are_fine_in_github_actions_without_eval(self):
        proc, env, out, _ = self.run_action({'my-key': 'v', 'a.b': 'w'}, INPUT_EVAL='false')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((env, out), ({}, {}))
        for line in proc.stdout.splitlines():
            self.assertTrue(line.startswith('::add-mask::'), line)

    def test_non_identifier_names_are_refused_when_shell_is_printed(self):
        proc, _, _, _ = self.run_action({'my-key': 'v'}, GITHUB_ACTIONS='', INPUT_EVAL='true')
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn('my-key=', proc.stdout)


if __name__ == '__main__':
    unittest.main()

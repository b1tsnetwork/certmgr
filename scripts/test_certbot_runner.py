#!/usr/bin/env python3
"""Unit tests for isolated DNS update credential generation."""
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import stat
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('certbot_runner', Path(__file__).with_name('certbot-runner.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RFC2136Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.secret_file = self.directory / 'tsig.ini'
        self.secret_file.write_text('dns_rfc2136_name = acme-update.\n'
                                    'dns_rfc2136_secret = abc123+/==\n'
                                    'dns_rfc2136_algorithm = HMAC-SHA512\n'
                                    'dns_rfc2136_server = 192.0.2.20\n')
        self.profile = {'id': 'internal', 'label': 'Internal', 'directory_url': 'https://acme.example.com/directory',
                        'email': 'admin@example.com', 'challenge': 'rfc2136',
                        'credentials_file': '/run/secrets/tsig.ini', 'dns_server': '10.20.30.40',
                        'dns_port': 5353, 'dns_propagation_seconds': 12}

    def test_generated_file_uses_webui_server_and_keeps_secret_in_worker(self):
        result, propagation = runner.prepare_rfc2136_credentials(self.profile, self.secret_file, self.directory / 'profiles' / 'internal')
        content = Path(result).read_text()
        self.assertIn('dns_rfc2136_server = 10.20.30.40', content)
        self.assertNotIn('192.0.2.20', content)
        self.assertIn('dns_rfc2136_port = 5353', content)
        self.assertIn('dns_rfc2136_secret = abc123+/==', content)
        self.assertIn('dns_rfc2136_algorithm = HMAC-SHA512', content)
        self.assertEqual(propagation, 12)
        self.assertEqual(stat.S_IMODE(os.stat(result).st_mode), 0o600)

    def test_invalid_ip_and_port_rejected(self):
        for v in ['localhost', '10.20.30.40;echo pwned', '0.0.0.0']:
            with self.subTest(value=v):
                data = dict(self.profile, dns_server=v)
                with self.assertRaises(ValueError):
                    runner.prepare_rfc2136_credentials(data, self.secret_file, self.directory / 'out')
        data = dict(self.profile, dns_port=65536)
        with self.assertRaises(ValueError):
            runner.prepare_rfc2136_credentials(data, self.secret_file, self.directory / 'out')

    def test_missing_tsig_secret_rejected(self):
        self.secret_file.write_text('dns_rfc2136_name = name.\n')
        with self.assertRaises(ValueError):
            runner.prepare_rfc2136_credentials(self.profile, self.secret_file, self.directory / 'out')

    def test_command_has_rfc2136_plugin_with_file_and_no_secret_in_args(self):
        def fake_restricted(path, prefix):
            self.assertEqual(path, '/run/secrets/tsig.ini')
            self.assertEqual(prefix, '/run/secrets/')
            return str(self.secret_file)
        with patch.object(runner, 'restricted_file', side_effect=fake_restricted), \
                patch.object(runner, 'prepare_rfc2136_credentials', return_value=('/private/credentials.ini', 12)):
            command, environment = runner.build_command(self.profile, {'name': 'web', 'expected_dns_names': ['server.example.com']})
        self.assertIn('--dns-rfc2136', command)
        self.assertIn('/private/credentials.ini', command)
        self.assertIn('--dns-rfc2136-propagation-seconds', command)
        self.assertNotIn('abc123+/==', repr(command))
        self.assertEqual(environment['CERTWATCH_ACME_PROFILE'], 'internal')

if __name__ == '__main__':
    unittest.main()

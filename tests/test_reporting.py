import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

import php2shell_reporting as rep
import php2shell_rescue as rescue


class ReportingTests(unittest.TestCase):
    def test_success_and_error_report_have_no_identifiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = pathlib.Path(tmp) / 'home'
            home.mkdir()
            with mock.patch.object(rep.pathlib.Path, 'home', return_value=home):
                diag = rep.DiagnosticSession('prepare', target_php='8.5.12', service='brew-user')
                diag.event('configuration', 'started')
                diag.finish(False, 'Command failed on /Users/someone/Secret/login - password=secret 192.0.2.99')
                obj = rep.get_report()
                text = json.dumps(obj)
                for secret in ('someone', 'Secret', 'password=', '192.0.2.99', '/Users/'):
                    self.assertNotIn(secret, text)
                self.assertEqual(obj['operation'], 'prepare')
                self.assertEqual(obj['result'], 'failure')
                self.assertEqual((home / '.php2shell-rescue/latest.json').stat().st_mode & 0o777, 0o600)

    def test_build_log_patterns_never_include_raw_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp)
            (path / 'make.log').write_text('fatal error: /Users/private/Documents/secret.h file not found\n'
                                           'Undefined symbols for architecture x86_64: hostname.private\n')
            got = rep.classify_build_logs(path)
            raw = json.dumps(got)
            self.assertIn('missing_header', raw)
            self.assertIn('undefined_symbol', raw)
            self.assertNotIn('/Users/', raw)
            self.assertNotIn('hostname.private', raw)

    def test_endpoint_requires_https_and_no_redirect_or_credentials(self):
        for endpoint in ('http://example.com/report.php', 'https://user:pw@site.test/report',
                         'https://site.test:8443/report', 'https://site.test/report?token=x'):
            with self.assertRaises(ValueError):
                rep.validate_endpoint(endpoint)
        self.assertEqual(rep.validate_endpoint('https://site.test/report.php'), 'https://site.test/report.php')
        self.assertEqual(rep.DEFAULT_ENDPOINT, 'https://code.stevenstromer.com/public/uploaders/php2shell_report.php')

    def test_report_exact_preview_and_cancel_does_not_upload(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp)
            diag = rep.DiagnosticSession('audit')
            diag.attach_work(work)
            diag.finish(True)
            with mock.patch('builtins.input', return_value='NO'), mock.patch.object(rep, 'submit_report') as submit:
                with mock.patch('sys.stdout', new_callable=io.StringIO) as stdout:
                    rep.report_command(work, endpoint='https://site.test/reports')
                self.assertIn('EXACT PAYLOAD', stdout.getvalue())
                self.assertIn('Nothing uploaded', stdout.getvalue())
                submit.assert_not_called()

    def test_report_rejects_unexpected_raw_logs(self):
        diag = rep.DiagnosticSession('audit')
        diag.finish(True)
        forged = dict(diag.data)
        forged['raw_config'] = 'private secret'
        with self.assertRaises(ValueError):
            rep.verify_report(forged)

    def test_corrupt_manifests_are_not_sent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'diagnostics.json'
            path.write_text('{"username":"sensitive"}')
            with self.assertRaises(ValueError):
                rep.get_report(tmp)


class DowngradePreventionTests(unittest.TestCase):
    def test_newer_patch_is_not_replaced(self):
        from test_rescue import TestCutover, r
        test = TestCutover('test_successful_deploy_then_explicit_rollback')
        test.setUp()
        try:
            def probe_factory(*args):
                p = test.docroot / 'temp-probe'
                p.write_text('test')
                def probe():
                    return dict(php='8.5.13', sapi='apache2handler',
                                modules=['json'], upload='0')
                return p, probe
            with mock.patch.object(r, 'make_probe', side_effect=probe_factory):
                with self.assertRaisesRegex(r.RescueError, 'refusing downgrade'):
                    r.deploy(test.opts)
            self.assertEqual(test.calls, [])
            self.assertEqual(test.conf.read_bytes(), test.original)
        finally:
            test.tearDown()

if __name__ == '__main__':
    unittest.main()

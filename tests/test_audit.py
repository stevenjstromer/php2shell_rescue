"""Regression tests for non-invasive compatibility assessment and beta invitations."""
import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

MAIN = pathlib.Path(__file__).resolve().parents[1] / "php2shell_rescue.py"
spec = importlib.util.spec_from_file_location("rescue_audit", MAIN)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.conf = self.base / "httpd.conf"
        self.conf.write_text("LoadModule php_module /usr/local/libphp.so\n")
        self.fake_paths = {
            "httpd": "/usr/local/bin/httpd", "conf": str(self.conf),
            "oldmodule": "/usr/local/libphp.so", "apxs": "/usr/local/bin/apxs"
        }
        self.patches = [
            mock.patch.object(r, "platform_check"),
            mock.patch.object(r, "apache_paths", return_value=self.fake_paths),
            mock.patch.object(r, "service_identity", return_value={"mode": "brew-user"}),
            mock.patch.object(r.reporting, "report_home", return_value=self.base),
            mock.patch.object(r.shutil, "which", side_effect=lambda name: "/usr/local/bin/" + name),
            mock.patch.object(r.pathlib.Path, "is_file", return_value=True),
            mock.patch.object(r.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="")),
            mock.patch.object(r, "cmd", side_effect=self.fake_cmd),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def fake_cmd(self, args, **kwargs):
        if "php-config" in args[0]:
            return SimpleNamespace(stdout="8.5.11\n", stderr="", returncode=0)
        if "xcode-select" in args[0]:
            return SimpleNamespace(stdout="/Library/Developer/CommandLineTools\n", stderr="", returncode=0)
        return SimpleNamespace(stdout="13.7.8\n", stderr="", returncode=0)

    def run_audit(self, *args):
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = r.main(["audit", *args])
        payload = json.loads((self.base / "latest.json").read_text())
        return code, out.getvalue(), err.getvalue(), payload

    def test_candidate_summary_and_opt_in_invitation(self):
        code, stdout, stderr, payload = self.run_audit()
        self.assertEqual(code, 0)
        self.assertIn("PRELIMINARY CANDIDATE", stdout)
        self.assertIn("INCLUDING SUCCESSFUL AUDITS", stdout)
        self.assertIn("nothing is uploaded unless you type SEND", stdout)
        self.assertEqual(payload["result"], "success")
        self.assertEqual(payload["error_code"], "NONE")
        self.assertNotIn("/usr/local", json.dumps(payload))
        r.reporting.verify_report(payload)

    def test_missing_build_tool_means_manual_review(self):
        def which(name):
            return None if name == "clang" else "/usr/local/bin/" + name
        with mock.patch.object(r.shutil, "which", side_effect=which):
            code, stdout, _, payload = self.run_audit()
        self.assertEqual(code, 0)  # Audit completed, even though machine isn't ready.
        self.assertIn("MANUAL REVIEW REQUIRED", stdout)
        self.assertIn("Required build tool clang", stdout)
        self.assertIn("python3 php2shell_rescue.py report", stdout)
        self.assertEqual(payload["result"], "failure")
        self.assertEqual(payload["error_code"], "CONFIGURATION_UNSUPPORTED")
        r.reporting.verify_report(payload)

    def test_unrecognized_service_is_manual_review_not_false_success(self):
        with mock.patch.object(r, "service_identity", side_effect=r.RescueError("no supported user httpd service")):
            code, stdout, _, payload = self.run_audit()
        self.assertEqual(code, 0)
        self.assertIn("MANUAL REVIEW REQUIRED", stdout)
        self.assertIn("--service", stdout)
        self.assertEqual(payload["result"], "failure")

    def test_unsupported_architecture_invites_audit_report(self):
        with mock.patch.object(r, "platform_check", side_effect=r.RescueError("Automatic operations require native Intel macOS (x86_64)")):
            code, stdout, stderr, payload = self.run_audit()
        self.assertEqual(code, 1)
        self.assertIn("UNSUPPORTED CONFIGURATION", stdout)
        self.assertIn("python3 php2shell_rescue.py report", stdout)
        self.assertIn("ERROR:", stderr)
        self.assertEqual(payload["result"], "failure")
        self.assertEqual(payload["error_code"], "CONFIGURATION_UNSUPPORTED")
        r.reporting.verify_report(payload)

    def test_system_service_can_be_selected_explicitly(self):
        with mock.patch.object(r, "service_identity", return_value={"mode": "launchd-system", "label": "org.example.httpd"}) as identity:
            code, stdout, _, payload = self.run_audit("--service", "launchd-system", "--launchd-plist", "/Library/LaunchDaemons/org.example.httpd.plist")
        self.assertEqual(code, 0)
        self.assertEqual(identity.call_args.args[0], "launchd-system")
        self.assertIn("MANUAL REVIEW REQUIRED", stdout)
        self.assertIn("separate deployment review", stdout)
        self.assertEqual(payload["result"], "failure")

    def test_actual_receiver_schema_remains_v1_compatible(self):
        _, _, _, payload = self.run_audit()
        self.assertEqual(payload["schema"], 1)
        self.assertEqual(set(payload), {
            "schema", "application", "application_version", "session", "started_at", "finished_at",
            "operation", "result", "stage", "error_code", "platform", "target_php", "service", "events", "build_errors"
        })


if __name__ == "__main__":
    unittest.main()

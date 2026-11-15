"""Opt-in, allowlisted diagnostic reporting for PHP2Shell Rescue.

No raw command output, paths, hostnames, environment, or configuration files
are included in transmitted reports. Python standard library only.
"""
from __future__ import annotations

import datetime
import json
import os
import pathlib
import platform
import re
import secrets
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

REPORT_SCHEMA = 1
CLIENT_VERSION = "0.3.4-beta"
DEFAULT_ENDPOINT = "https://code.stevenstromer.com/public/uploaders/php2shell_report.php"
OPERATIONS = {"audit", "prepare", "deploy", "rollback", "status"}
OUTCOMES = {"started", "passed", "failed"}
STAGES = {
    "initializing", "environment", "apache-discovery", "service-discovery",
    "source-download", "source-verification", "configuration", "compilation",
    "candidate-verification", "manifest", "preflight", "http-baseline",
    "backup", "authorization", "apache-configuration", "apache-restart",
    "http-verification", "automatic-rollback", "manual-rollback", "complete"
}
ERROR_CODES = {
    "NONE", "REJECTED", "COMMAND_FAILED", "MISSING_DEPENDENCY", "CONFIGURE_FAILED",
    "COMPILE_FAILED", "SOURCE_INTEGRITY_FAILED", "CONFIGURATION_UNSUPPORTED",
    "PREPARED_BUILD_INVALID", "RESTART_FAILED", "HTTP_VERIFICATION_FAILED",
    "ROLLBACK_UNVERIFIED", "USER_CANCELLED", "INTERNAL_ERROR"
}
BUILD_ERROR_CLASSES = {
    "missing_header", "missing_library", "pkg_config_dependency", "compiler_error",
    "linker_error", "undefined_symbol", "missing_command", "configuration_error",
    "other_error"
}


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_version(value):
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){1,3}", value):
        return value
    return None


def save_private(path, obj, uid=None, gid=None):
    path = pathlib.Path(path)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise OSError("Diagnostic parent directory must exist and not be a symlink")
    data = (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=".report-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp_name, 0o600)
        if uid is not None and os.geteuid() == 0:
            os.chown(temp_name, uid, gid)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def report_home():
    folder = pathlib.Path.home() / ".php2shell-rescue"
    if folder.is_symlink():
        raise OSError("Diagnostic directory must not be a symlink")
    if not folder.exists():
        folder.mkdir(mode=0o700)
    if stat.S_IMODE(folder.stat().st_mode) & 0o077:
        raise OSError("Diagnostic directory must be private (0700)")
    return folder


def classify_error(message, stage):
    text = str(message).lower()
    if text.startswith("audit readiness manual review"):
        return "CONFIGURATION_UNSUPPORTED"
    if "cancelled" in text or "not approved" in text:
        return "USER_CANCELLED"
    if "rollback" in text and ("unverified" in text or "manual" in text):
        return "ROLLBACK_UNVERIFIED"
    if "checksum" in text or "sha256" in text and "mismatch" in text:
        return "SOURCE_INTEGRITY_FAILED" if stage in ("source-download", "source-verification") else "PREPARED_BUILD_INVALID"
    if stage == "compilation":
        return "COMPILE_FAILED"
    if stage == "configuration":
        return "CONFIGURE_FAILED"
    if stage == "apache-restart":
        return "RESTART_FAILED"
    if stage in ("http-baseline", "http-verification"):
        return "HTTP_VERIFICATION_FAILED"
    if "not found" in text or "missing" in text:
        return "MISSING_DEPENDENCY"
    if "unsupported" in text or "require" in text or "refusing" in text:
        return "CONFIGURATION_UNSUPPORTED"
    if "command failed" in text:
        return "COMMAND_FAILED"
    return "REJECTED"


def classify_build_logs(work):
    """Return ONLY counts of error classes; never source log text or paths."""
    if work is None:
        return []
    work = pathlib.Path(work)
    counts = {}
    for name in ("configure.log", "make.log"):
        path = work / name
        if not path.is_file() or path.is_symlink():
            continue
        with path.open("rb") as stream:
            # Inspect only the final 256 KiB, where failed commands normally
            # leave their diagnostic errors. No original lines leave the host.
            stream.seek(max(0, path.stat().st_size - 262144))
            if stream.tell():
                stream.readline()  # Skip a possible truncated first line.
            for raw in stream:
                line = raw[:2048].decode("utf-8", errors="replace").lower()
                category = None
                if "no such file or directory" in line or "file not found" in line:
                    category = "missing_header"
                elif "package" in line and ("not found" in line or "was not found" in line):
                    category = "pkg_config_dependency"
                elif "library not found" in line or "cannot find -l" in line:
                    category = "missing_library"
                elif "undefined symbol" in line or "undefined symbols" in line:
                    category = "undefined_symbol"
                elif "command not found" in line or "not found: command" in line:
                    category = "missing_command"
                elif "ld: " in line or "linker command failed" in line:
                    category = "linker_error"
                elif "error:" in line and name == "configure.log":
                    category = "configuration_error"
                elif "error:" in line or "fatal error" in line:
                    category = "compiler_error"
                if category:
                    counts[category] = min(9999, counts.get(category, 0) + 1)
    return [{"class": name, "count": count} for name, count in sorted(counts.items())]


class DiagnosticSession:
    def __init__(self, operation, target_php=None, service=None, work=None):
        # Never write into --work until the calling operation validates it.
        self.work = None
        self.stage = "initializing"
        self.data = {
            "schema": REPORT_SCHEMA,
            "application": "php2shell-rescue",
            "application_version": CLIENT_VERSION,
            "session": secrets.token_hex(12),
            "started_at": utc_now(),
            "operation": operation,
            "result": "started",
            "stage": "initializing",
            "error_code": "NONE",
            "platform": {
                "os": "macOS" if sys.platform == "darwin" else "other",
                "version": safe_version(platform.mac_ver()[0]) if sys.platform == "darwin" else None,
                "architecture": platform.machine() if platform.machine() in ("x86_64", "arm64") else "other"
            },
            "target_php": safe_version(target_php),
            "service": service if service in ("brew-user", "launchd-system") else "unknown",
            "events": [],
            "build_errors": []
        }
        self.event("initializing", "started")

    def attach_work(self, work):
        self.work = pathlib.Path(work).expanduser().absolute()
        self._save()

    def _save(self):
        # Local logging must never prevent a security update or rollback.
        try:
            home = report_home()
            save_private(home / "latest.json", self.data)
        except (OSError, ValueError):
            pass
        if self.work and self.work.is_dir() and not self.work.is_symlink():
            try:
                info = self.work.stat()
                save_private(self.work / "diagnostics.json", self.data,
                             info.st_uid, info.st_gid)
            except (OSError, ValueError):
                pass

    def event(self, stage, outcome):
        if stage not in STAGES or outcome not in OUTCOMES:
            raise ValueError("Invalid diagnostic stage/outcome")
        self.stage = stage
        self.data["stage"] = stage
        self.data["events"].append({"stage": stage, "outcome": outcome})
        self.data["events"] = self.data["events"][-40:]
        self._save()

    def finish(self, success, message=""):
        self.data["result"] = "success" if success else "failure"
        self.data["error_code"] = "NONE" if success else classify_error(message, self.stage)
        if success:
            self.event("complete", "passed")
        else:
            self.event(self.stage, "failed")
        if self.data["operation"] == "prepare":
            self.data["build_errors"] = classify_build_logs(self.work)
        self.data["finished_at"] = utc_now()
        self._save()


def verify_report(payload):
    if not isinstance(payload, dict) or set(payload) != {
        "schema", "application", "application_version", "session", "started_at",
        "finished_at", "operation", "result", "stage", "error_code", "platform",
        "target_php", "service", "events", "build_errors"
    }:
        raise ValueError("Invalid report fields")
    if payload["schema"] != REPORT_SCHEMA or payload["application"] != "php2shell-rescue":
        raise ValueError("Unsupported report format")
    if not re.fullmatch(r"[a-zA-Z0-9.-]{1,32}", payload["application_version"]):
        raise ValueError("Invalid client version")
    if not re.fullmatch(r"[a-f0-9]{24}", payload["session"]):
        raise ValueError("Invalid session identifier")
    if payload["operation"] not in OPERATIONS or payload["result"] not in ("success", "failure", "interrupted"):
        raise ValueError("Invalid operation or result")
    if payload["stage"] not in STAGES or payload["error_code"] not in ERROR_CODES:
        raise ValueError("Invalid stage or error code")
    if payload["service"] not in ("brew-user", "launchd-system", "unknown"):
        raise ValueError("Invalid service")
    for key in ("started_at", "finished_at"):
        if not isinstance(payload[key], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", payload[key]):
            raise ValueError("Invalid timestamp")
    p = payload["platform"]
    if not isinstance(p, dict) or set(p) != {"os", "version", "architecture"}:
        raise ValueError("Invalid platform")
    if p["os"] not in ("macOS", "other") or p["architecture"] not in ("x86_64", "arm64", "other"):
        raise ValueError("Invalid platform values")
    if p["version"] is not None and safe_version(p["version"]) != p["version"]:
        raise ValueError("Invalid platform version")
    if payload["target_php"] is not None and safe_version(payload["target_php"]) != payload["target_php"]:
        raise ValueError("Invalid PHP version")
    if not isinstance(payload["events"], list) or not (1 <= len(payload["events"]) <= 40):
        raise ValueError("Invalid events")
    for event in payload["events"]:
        if not isinstance(event, dict) or set(event) != {"stage", "outcome"}:
            raise ValueError("Invalid event")
        if event["stage"] not in STAGES or event["outcome"] not in OUTCOMES:
            raise ValueError("Invalid event value")
    if not isinstance(payload["build_errors"], list) or len(payload["build_errors"]) > len(BUILD_ERROR_CLASSES):
        raise ValueError("Invalid build errors")
    for signature in payload["build_errors"]:
        if not isinstance(signature, dict) or set(signature) != {"class", "count"}:
            raise ValueError("Invalid build error")
        if signature["class"] not in BUILD_ERROR_CLASSES or not isinstance(signature["count"], int) or signature["count"] < 1 or signature["count"] > 9999:
            raise ValueError("Invalid build error values")
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(encoded) > 16384:
        raise ValueError("Report exceeds maximum size")
    return encoded


def get_report(work=None):
    source = (pathlib.Path(work).expanduser().absolute() / "diagnostics.json"
              if work else report_home() / "latest.json")
    if source.is_symlink() or not source.is_file():
        raise ValueError("No diagnostic report found; run an audit or another command first")
    payload = json.loads(source.read_text(encoding="utf-8"))
    if "finished_at" not in payload:
        # A power loss or forced termination can leave a useful partial journal.
        payload = dict(payload)
        payload["finished_at"] = utc_now()
        payload["result"] = "interrupted"
        payload["error_code"] = "INTERNAL_ERROR"
        payload["events"] = (payload.get("events", []) +
                             [{"stage": payload.get("stage", "initializing"), "outcome": "failed"}])[-40:]
    verify_report(payload)
    return payload


def validate_endpoint(endpoint):
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 443):
        raise ValueError("Reporting endpoint must be an ordinary HTTPS URL (port 443)")
    return endpoint


def submit_report(payload, endpoint=DEFAULT_ENDPOINT):
    endpoint = validate_endpoint(endpoint)
    body = verify_report(payload)
    request = urllib.request.Request(endpoint, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "php2shell-rescue/0.3.4"
    })
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=15) as response:
        result = json.loads(response.read(2048).decode("utf-8"))
    identifier = result.get("report_id") if isinstance(result, dict) else None
    if not isinstance(identifier, str) or not re.fullmatch(r"P2S-[a-fA-F0-9]{12}", identifier):
        raise ValueError("Receiver did not return a valid report identifier")
    return identifier


def report_command(work=None, endpoint=DEFAULT_ENDPOINT):
    report = get_report(work)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print("\nPHP2Shell Rescue diagnostic report: EXACT PAYLOAD BELOW\n")
    print(rendered)
    print("\nNo raw build logs, network configuration, user paths or hostnames are included.")
    print("The receiving server may separately log your public IP address.")
    print("The report is kept for up to 30 days; submission is optional.")
    print("Endpoint:", validate_endpoint(endpoint))
    try:
        approved = input("\nType SEND to submit this exact report (anything else cancels): ")
    except (EOFError, KeyboardInterrupt):
        approved = ""
    if approved != "SEND":
        print("Cancelled. Nothing uploaded.")
        return
    identifier = submit_report(report, endpoint)
    print("Report received. Tracking ID:", identifier)

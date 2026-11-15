#!/usr/bin/env python3
"""Emergency PHP2Shell source build + guarded Apache/mod_php switchover.

Scope: Intel macOS with Homebrew Apache/mod_php. Supports explicit user
brew services or direct-httpd system LaunchDaemons; no PHP-FPM, multi-
LoadModule, or Apple Apache automatic deployment. Read README.md first.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error

import php2shell_reporting as reporting
from datetime import datetime, timezone

RELEASES = {
    "8.2.35": "5737b98601fe5ab1b8c5db0c82ed3158acb9283ed3081ffe2faffb9ac81455e6",
    "8.3.36": "dd54693aa334c5c4d72e9aee96b082c2473750a18a6c1d105789c93a3b1692fd",
    "8.4.27": "dcf93923b0e38e0d5252b25b796520b5a47761a08b3488b6d0b5d1115764d3f0",
    "8.5.12": "08bc2eba2a588654ade1357174aa646b761556c862dda0678345ee29ed481209",
}
MOD_RE = re.compile(rb'^(?P<indent>[ \t]*)LoadModule[ \t]+(?P<name>php(?:[0-9]+)?_module)[ \t]+(?P<path>[^\r\n#]+?)[ \t]*(?:\r?\n|$)', re.M)
BLOCK_START = b"# BEGIN PHP2SHELL-RESCUE MANAGED\n"
BLOCK_END = b"# END PHP2SHELL-RESCUE MANAGED\n"

# The diagnostics record fixed stage identifiers only, never raw command output.
_DIAGNOSTIC_SESSION = None


def trace(stage):
    if _DIAGNOSTIC_SESSION is not None:
        _DIAGNOSTIC_SESSION.event(stage, "started")


def attach_diagnostics(work):
    if _DIAGNOSTIC_SESSION is not None:
        _DIAGNOSTIC_SESSION.attach_work(work)


class RescueError(Exception):
    pass


def die(message):
    raise RescueError(message)


def log(message):
    print(message, flush=True)


def now():
    return datetime.now(timezone.utc).isoformat()


def digest_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for buf in iter(lambda: f.read(1024 * 1024), b""):
            h.update(buf)
    return h.hexdigest()


def cmd(args, *, check=True, env=None, cwd=None, stdout=None):
    e = os.environ.copy()
    e["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    if env:
        e.update(env)
    proc = subprocess.run(args, cwd=cwd, env=e, text=True,
                          stdout=stdout if stdout is not None else subprocess.PIPE,
                          stderr=subprocess.PIPE)
    if check and proc.returncode:
        details = (proc.stderr or proc.stdout or "")[-1500:]
        die(f"Command failed ({proc.returncode}): {args[0]}: {details.strip()}")
    return proc


def atomic_bytes(path, data, mode=None):
    path = pathlib.Path(path)
    info = path.stat() if path.exists() else None
    fd, temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        if info:
            os.chmod(temp, stat.S_IMODE(info.st_mode))
            try:
                os.chown(temp, info.st_uid, info.st_gid)
            except PermissionError:
                if info.st_uid != os.geteuid():
                    die("Cannot preserve Apache configuration ownership")
        else:
            os.chmod(temp, 0o600 if mode is None else mode)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def save_manifest(work, m):
    atomic_bytes(pathlib.Path(work) / "manifest.json",
                 (json.dumps(m, indent=2, sort_keys=True) + "\n").encode(), mode=0o600)


def load_manifest(work):
    p = pathlib.Path(work) / "manifest.json"
    if not p.exists() or p.is_symlink():
        die("No trusted local manifest; run prepare first")
    if (p.stat().st_uid != os.geteuid() and os.geteuid() != 0) or p.stat().st_mode & 0o077:
        die("Manifest is not owner-only (0600) or is owned by another user")
    m = json.loads(p.read_text())
    if m.get("schema") != 1 or m.get("state") not in ("prepared", "pending", "deployed", "rolled_back"):
        die("Unexpected manifest format or state")
    return m


def platform_check(allow_root=False):
    if sys.platform != "darwin" or os.uname().machine != "x86_64":
        die("Automatic operations require native Intel macOS (x86_64)")
    if os.geteuid() == 0 and not allow_root:
        die("Run as a normal user (root is permitted only for explicit system LaunchDaemon cutover)")


def executable(path, fallback=None):
    p = pathlib.Path(path or fallback or "")
    if p.is_file() and os.access(p, os.X_OK):
        return str(p.resolve())
    die(f"Required executable not found: {p}")


def config_entry(config):
    raw = pathlib.Path(config).read_bytes()
    if BLOCK_START in raw or BLOCK_END in raw:
        die("Configuration already contains a managed PHP2Shell block; use rollback or restore first")
    hits = list(MOD_RE.finditer(raw))
    if len(hits) != 1:
        die("Require exactly one direct, uncommented PHP LoadModule line in the selected httpd.conf")
    hit = hits[0]
    try:
        args = shlex.split(hit.group("path").decode().strip())
    except ValueError:
        die("Unsupported PHP module path syntax")
    if len(args) != 1:
        die("Unsupported PHP module LoadModule syntax")
    return raw, hit, args[0]


def apache_paths(opts):
    conf = pathlib.Path(opts.conf or "/usr/local/etc/httpd/httpd.conf").resolve()
    if not conf.is_file() or conf.is_symlink():
        die("Apache configuration must be a regular, existing file")
    httpd = executable(opts.httpd, "/usr/local/opt/httpd/bin/httpd")
    apxs = executable(opts.apxs, "/usr/local/opt/httpd/bin/apxs")
    # Confirm we are not accidentally operating against Apple's Apache.
    for value in (str(conf), httpd, apxs):
        if not (value == "/usr/local" or value.startswith("/usr/local/")):
            die("Automatic deployment only supports Homebrew Apache under /usr/local")
    server_build = cmd([httpd, "-V"]).stdout
    config_match = re.search(r'-D SERVER_CONFIG_FILE="([^"]+)"', server_build)
    root_match = re.search(r'-D HTTPD_ROOT="([^"]+)"', server_build)
    if config_match and root_match:
        default_conf = pathlib.Path(root_match.group(1)) / config_match.group(1)
        if default_conf.resolve() != conf:
            die("Specified httpd.conf differs from Apache's compiled default. Refuse automatic cutover.")
    else:
        die("Could not verify Apache's compiled configuration path")
    config_test = cmd([httpd, "-t", "-f", str(conf)], check=False)
    if config_test.returncode:
        if getattr(opts, "service", None) == "launchd-system" and os.geteuid() != 0:
            log("WARNING: Unprivileged Apache config test failed; root deployment will re-test before switchover.")
        else:
            die("Apache configuration test failed: " + config_test.stderr.strip()[-600:])
    raw, hit, oldpath = config_entry(conf)
    if oldpath.startswith('"') or oldpath.startswith("'"):
        die("Unsupported quoted PHP path format")
    if not oldpath.startswith("/"):
        die("Require absolute LoadModule path; relative paths need manual review")
    oldmodule = pathlib.Path(oldpath).resolve()
    if not oldmodule.is_file():
        die(f"Currently configured PHP module is missing: {oldmodule}")
    return {"conf": str(conf), "httpd": httpd, "apxs": apxs,
            "oldmodule": str(oldmodule), "raw": raw, "hit": hit}


def brew_status():
    brew = executable(shutil.which("brew"), "/usr/local/bin/brew")
    if not brew.startswith("/usr/local/"):
        die("Only Intel Homebrew under /usr/local is supported")
    p = cmd([brew, "services", "list"])
    rows = [line.split() for line in p.stdout.splitlines() if line.split()]
    matches = [r for r in rows if r[0] == "httpd"]
    if len(matches) != 1 or len(matches[0]) < 3:
        die("No unambiguous Homebrew httpd service found")
    status, owner = matches[0][1:3]
    import getpass
    if status != "started" or owner != getpass.getuser():
        die(f"Expected 'httpd started {getpass.getuser()}' from brew services list; found {status} {owner}")
    return brew


def system_launchd_identity(plist_path, httpd):
    p = pathlib.Path(plist_path)
    if p.is_symlink() or not p.is_file() or not str(p).startswith("/Library/LaunchDaemons/"):
        die("System service must be an ordinary plist under /Library/LaunchDaemons")
    with open(p, "rb") as f:
        data = plistlib.load(f)
    args = data.get("ProgramArguments", [])
    if not isinstance(args, list) or not args or not isinstance(args[0], str):
        die("System LaunchDaemon requires explicit ProgramArguments")
    if not pathlib.Path(args[0]).is_file() or pathlib.Path(args[0]).resolve() != pathlib.Path(httpd).resolve():
        die("System LaunchDaemon must directly execute the selected Homebrew httpd binary")
    if any(arg == "-f" or arg.startswith("-f") for arg in args[1:] if isinstance(arg, str)):
        die("Custom -f Apache config overrides are not supported by this LaunchDaemon adapter")
    label = data.get("Label")
    if not isinstance(label, str) or not label or not all(c.isalnum() or c in "-_." for c in label):
        die("LaunchDaemon has no safe Label")
    if data.get("Disabled"):
        die("LaunchDaemon is disabled")
    return {"mode": "launchd-system", "plist": str(p), "label": label,
            "plist_sha": digest(p)}


def service_identity(mode, opts, httpd):
    if mode == "brew-user":
        return {"mode": mode, "brew": brew_status()}
    if mode == "launchd-system":
        if not opts.launchd_plist:
            die("--launchd-plist required for launchd-system service")
        return system_launchd_identity(opts.launchd_plist, httpd)
    die("Unsupported service mode")


def verify_service_identity(identity, httpd):
    if identity["mode"] == "brew-user":
        if os.geteuid() == 0 or brew_status() != identity["brew"]:
            die("Homebrew Apache user service identity changed")
    elif identity["mode"] == "launchd-system":
        if os.geteuid() != 0:
            die("System LaunchDaemon deploy/rollback must be invoked using sudo")
        updated = system_launchd_identity(identity["plist"], httpd)
        if updated != identity:
            die("System LaunchDaemon definition changed since prepare")
        cmd(["/bin/launchctl", "print", "system/" + identity["label"]])
    else:
        die("Unsupported service identity")


def audit_summary(readiness, reasons):
    """Present a conservative assessment, not authorization to deploy."""
    labels = {
        "candidate": "PRELIMINARY CANDIDATE",
        "review": "MANUAL REVIEW REQUIRED",
        "unsupported": "UNSUPPORTED CONFIGURATION",
        "incomplete": "INCOMPLETE — MANUAL REVIEW REQUIRED",
    }
    log("\n=== AUDIT READINESS: " + labels[readiness] + " ===")
    for reason in reasons:
        log("- " + reason)
    if readiness == "candidate":
        log("Checks passed for initial eligibility, NOT for compilation or live deployment.")
    elif readiness == "review":
        log("Do not proceed to live deployment until every issue is resolved.")
    elif readiness == "unsupported":
        log("Automatic installation is not supported for this configuration.")
    else:
        log("The audit did not complete; deployment suitability is unknown.")
    log("Even a promising audit does NOT verify PHP build, extensions, or HTTP cutover.")


def audit_report_invitation():
    log("\nBETA TESTERS: PLEASE SHARE YOUR AUDIT RESULTS (INCLUDING SUCCESSFUL AUDITS).")
    log("Run: python3 php2shell_rescue.py report")
    log("The exact sanitized JSON is shown for review; nothing is uploaded unless you type SEND.")
    log("Raw configuration, compiler output, usernames, paths and hostnames are not submitted.")


def doctor(opts):
    """Return True only for an initial candidate, False for manual review.

    Hard incompatibilities raise RescueError and are reported as unsupported by
    main(). This deliberately does not claim a safe production installation.
    """
    trace("environment")
    platform_check()
    trace("apache-discovery")
    paths = apache_paths(opts)
    trace("service-discovery")
    issues = []
    log("SYSTEM: " + cmd(["/usr/bin/sw_vers", "-productVersion"]).stdout.strip())
    log("ARCHITECTURE: " + os.uname().machine)
    log("APACHE: " + paths["httpd"])
    log("HTTPD CONFIG: " + paths["conf"])
    log("OLD MODULE: " + paths["oldmodule"])
    log("APXS: " + paths["apxs"])
    log("CONFIG SHA256: " + digest(paths["conf"]))
    try:
        identity = service_identity(opts.service, opts, paths["httpd"])
        log("SELECTED SERVICE: " + identity["mode"])
        if identity["mode"] == "launchd-system":
            check = cmd(["/bin/launchctl", "print", "system/" + identity["label"]], check=False)
            if check.returncode:
                issues.append(("service-discovery", "Selected LaunchDaemon could not be confirmed running; review its service status."))
            else:
                log("SYSTEM LAUNCHDAEMON: recognized and visible to launchctl")
            issues.append(("service-discovery", "System LaunchDaemon cutover requires sudo and a separate deployment review."))
    except (RescueError, OSError, subprocess.SubprocessError) as exc:
        # Do not echo private service IDs or absolute paths in the readiness label.
        log("SERVICE CONFIGURATION: " + str(exc))
        issues.append(("service-discovery", "Selected Apache service mechanism is not confirmed compatible; choose/review --service."))
    for name in ("php", "php-config", "clang", "make", "pkg-config"):
        found = shutil.which(name)
        log(f"{name}: {found or 'NOT FOUND'}")
        if not found and name in ("clang", "make"):
            issues.append(("configuration", "Required build tool " + name + " was not found in PATH."))
        elif not found and name == "php-config":
            issues.append(("configuration", "php-config not found; a reviewed --configure-file is required to prepare."))
        elif not found and name == "pkg-config":
            issues.append(("configuration", "pkg-config not found; dependency discovery may require manual configuration."))
    for executable_path in ("/usr/bin/curl", "/usr/bin/tar", "/usr/bin/make", "/usr/bin/otool"):
        if not pathlib.Path(executable_path).is_file():
            issues.append(("configuration", "Required build/verification command not found: " + executable_path))
    clt = cmd(["/usr/bin/xcode-select", "-p"], check=False)
    if clt.returncode:
        issues.append(("configuration", "Xcode Command Line Tools are not available or not selected."))
    php_config = shutil.which("php-config")
    if php_config:
        installed = cmd([php_config, "--version"], check=False)
        if installed.returncode:
            issues.append(("configuration", "php-config version could not be read; review PHP build flags."))
        else:
            detected = installed.stdout.strip()
            log("PHP-CONFIG VERSION (not necessarily Apache PHP): " + detected)
            parts = detected.split(".")
            if len(parts) < 3 or not all(part.isdigit() for part in parts[:3]):
                issues.append(("configuration", "php-config version is not recognizable; review the current PHP branch."))
            elif ".".join(parts[:2]) not in {"8.2", "8.3", "8.4", "8.5"}:
                issues.append(("configuration", "php-config branch is outside the supported 8.2–8.5 release range."))
    import subprocess as _sp
    running_fpm = _sp.run(["/bin/ps", "-axo", "command"], capture_output=True, text=True, check=False)
    if any("php-fpm" in line and "grep" not in line for line in running_fpm.stdout.splitlines()):
        log("WARNING: PHP-FPM processes detected. This tool only patches Apache mod_php, not FPM.")
        issues.append(("service-discovery", "PHP-FPM detected; it will not be patched by this tool."))
    log("WARNING: A CLI php -v does not prove which PHP Apache serves.")
    log("WARNING: Audit paths and configuration may be sensitive; do not publish raw output.")
    if issues:
        # Preserve useful stage categories without transmitting raw paths or
        # free-form warning text (receiver schema 1 is unchanged).
        if _DIAGNOSTIC_SESSION is not None:
            for stage in dict.fromkeys(stage for stage, _ in issues):
                _DIAGNOSTIC_SESSION.event(stage, "failed")
        audit_summary("review", [reason for _, reason in issues])
        return False
    audit_summary("candidate", ["Intel macOS, Homebrew mod_php configuration, service, and basic tools detected."])
    return True


def infer_flags(apxs, dest, version, overrides=None):
    if overrides:
        data = pathlib.Path(overrides).read_text()
        flags = [s.strip() for s in data.splitlines() if s.strip() and not s.lstrip().startswith("#")]
    else:
        php_config = shutil.which("php-config")
        if not php_config:
            die("php-config not found: provide --configure-file with reviewed options")
        configured_version = cmd([php_config, "--version"]).stdout.strip()
        if configured_version.split(".")[:2] != version.split(".")[:2]:
            die("php-config is from a different PHP minor branch; use --configure-file with reviewed flags")
        output = cmd([php_config, "--configure-options"]).stdout.strip()
        flags = shlex.split(output)
    drop = ("--prefix=", "--with-apxs2",
            "--enable-fpm", "--disable-fpm", "--disable-cli", "--enable-cli")
    flags = [f for f in flags if not f.startswith(drop)]
    # Staged output has an independent prefix. Config locations from existing
    # PHP are deliberately reused only when confirmed by active runtime probes.
    flags.extend([f"--prefix={dest}", f"--with-apxs2={apxs}", "--enable-cli"])
    for f in flags:
        if not f.startswith("-") or "\n" in f:
            die(f"Malformed configure argument: {f!r}")
    return flags


def unpack_verified_tar(archive, destination, version):
    # The archive has already matched the official release's pinned SHA-256.
    # Use the system tar to preserve legitimate upstream file types and metadata.
    cmd(["/usr/bin/tar", "-xJf", str(archive), "-C", str(destination)])
    source = pathlib.Path(destination) / f"php-{version}"
    if not (source / "configure").is_file():
        die("Official archive extraction did not contain PHP configure")



def prepare(opts):
    trace("environment")
    platform_check()
    trace("apache-discovery")
    paths = apache_paths(opts)
    version = opts.version
    if version not in RELEASES:
        die("Only pinned security releases are supported")
    trace("service-discovery")
    identity = service_identity(opts.service, opts, paths["httpd"])
    work = pathlib.Path(opts.work).expanduser().absolute()
    if work.exists() or work.is_symlink():
        die("Work directory already exists; refusing to overwrite")
    if not work.parent.is_dir():
        die("Work directory parent does not exist")
    work.mkdir(mode=0o700)
    attach_diagnostics(work)
    if work.resolve() != work:
        die("Work directory must not contain symlink components")
    src = work / f"php-{version}"
    candidate = work / "candidate"
    prefix = str(candidate / "prefix")
    trace("configuration")
    flags = infer_flags(paths["apxs"], prefix, version, opts.configure_file)
    if opts.jobs not in (1, 2):
        die("Only 1 or 2 build jobs supported (thermal conservatism)")
    (work / "configure-arguments.txt").write_text("\n".join(flags) + "\n")
    uri = f"https://www.php.net/distributions/php-{version}.tar.xz"
    archive = work / f"php-{version}.tar.xz"
    trace("source-download")
    log("Downloading authenticated PHP release from php.net")
    cmd(["/usr/bin/curl", "--fail", "--location", "--retry", "2", "--proto", "=https", "--tlsv1.2", "-o", str(archive), uri])
    trace("source-verification")
    if digest(archive) != RELEASES[version]:
        die("Downloaded PHP source SHA256 does not match pinned upstream release")
    log("Source checksum verified: " + RELEASES[version])
    unpack_verified_tar(archive, work, version)
    env = {k: os.environ[k] for k in ("CPPFLAGS", "LDFLAGS", "LIBS", "PKG_CONFIG_PATH", "CFLAGS") if k in os.environ}
    log("Configuring PHP (no production changes)")
    with open(work / "configure.log", "w") as out:
        p = cmd([str(src / "configure"), *flags], cwd=src, env=env, stdout=out, check=False)
    if p.returncode:
        die("Configure failed. Inspect configure.log; no services changed. " + p.stderr[-500:])
    trace("compilation")
    log("Compiling PHP (no production changes)")
    with open(work / "make.log", "w") as out:
        p = cmd(["/usr/bin/make", "-j", str(opts.jobs)], cwd=src, env=env, stdout=out, check=False)
    if p.returncode:
        die("Build failed. Inspect make.log; no services changed. " + p.stderr[-500:])
    trace("candidate-verification")
    if not (src / "sapi/cli/php").is_file():
        die("PHP CLI executable missing after successful make")
    candidate.mkdir(mode=0o700)
    shutil.copy2(src / "sapi/cli/php", candidate / "php")
    modules = [src / "libs/libphp.bundle", src / "libs/libphp.so"]
    if not any(p.is_file() for p in modules):
        die("Apache mod_php module missing; did configure include --with-apxs2?")
    shutil.copy2(next(p for p in modules if p.is_file()), candidate / "libphp.so")
    result = cmd([str(candidate / "php"), "-n", "-r", "echo PHP_VERSION;"]).stdout.strip()
    if result != version:
        die(f"Built PHP reports {result!r}, expected {version}")
    cmd(["/usr/bin/otool", "-L", str(candidate / "libphp.so")])
    manifest = {"schema": 1, "state": "prepared", "created": now(), "version": version,
                "conf": paths["conf"], "httpd": paths["httpd"], "apxs": paths["apxs"],
                "service": identity, "config_sha": digest(paths["conf"]),
                "module_sha": digest(candidate / "libphp.so"), "cli_sha": digest(candidate / "php"),
                "oldmodule": paths["oldmodule"], "oldmodule_sha": digest(paths["oldmodule"]),
                "old_line": paths["hit"].group(0).decode(), "flags": flags}
    trace("manifest")
    save_manifest(work, manifest)
    log("PREPARED: " + str(work))
    log("No live service changed. Continue with deploy after reviewing logs, modules and prerequisites.")


def validate_probe_base(base):
    p = urllib.parse.urlsplit(base)
    if p.scheme != "http" or p.hostname not in ("127.0.0.1", "::1") or p.username or p.password or p.query or p.fragment:
        die("--probe-base must be a loopback-only http://127.0.0.1[:port][/path] URL")
    if not p.path.endswith("/") and p.path:
        die("--probe-base path must end in /")
    return base.rstrip("/") + "/"


def make_probe(probe_dir, probe_base, host_header=None):
    base = validate_probe_base(probe_base)
    directory = pathlib.Path(probe_dir)
    if not directory.is_dir() or directory.is_symlink():
        die("Probe directory must be an existing writable web directory")
    token = secrets.token_hex(32)
    file_name = ".php2shell-check-" + secrets.token_hex(16) + ".php"
    path = directory / file_name
    php = ("<?php\n"
           "$ip = $_SERVER['REMOTE_ADDR'] ?? '';\n"
           "if (!in_array($ip, ['127.0.0.1','::1'], true) || "
           "!hash_equals('" + token + "', $_GET['k'] ?? '')) "
           "{ http_response_code(404); exit; }\n"
           "header('Content-Type: application/json');\n"
           "echo json_encode(['php'=>PHP_VERSION,'sapi'=>PHP_SAPI,"
           "'modules'=>get_loaded_extensions(),"
           "'upload'=>(string)ini_get('session.upload_progress.enabled')]);\n")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    with os.fdopen(fd, "w") as out:
        out.write(php)
    url = base + urllib.parse.quote(file_name) + "?k=" + token
    def probe():
        req = urllib.request.Request(url, headers={"Host": host_header} if host_header else {})
        class DenyRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), DenyRedirect())
        with opener.open(req, timeout=8) as res:
            if res.status != 200:
                die("HTTP probe returned non-200")
            data = res.read(32768)
        obj = json.loads(data)
        if not all(k in obj for k in ("php", "sapi", "modules", "upload")):
            die("Invalid PHP runtime probe response")
        if obj["sapi"] != "apache2handler":
            die("The probed URL is not handled by mod_php")
        return obj
    return path, probe


def change_config(original, module_path, name, mitigation):
    hits = list(MOD_RE.finditer(original))
    if len(hits) != 1 or BLOCK_START in original:
        die("Apache PHP LoadModule line changed unexpectedly")
    directive = hits[0].group("indent") + b"LoadModule " + name.encode() + b" " + str(module_path).encode() + b"\n"
    block = BLOCK_START + directive
    if mitigation:
        block += b"<IfModule " + name.encode() + b">\n    php_admin_flag session.upload_progress.enabled Off\n</IfModule>\n"
    block += BLOCK_END
    return original[:hits[0].start()] + block + original[hits[0].end():]


def service(identity, mode):
    if mode not in ("stop", "start"):
        die("Unsupported service operation")
    if identity["mode"] == "brew-user":
        cmd([identity["brew"], "services", mode, "httpd"])
    elif identity["mode"] == "launchd-system":
        operation = "bootout" if mode == "stop" else "bootstrap"
        cmd(["/bin/launchctl", operation, "system", identity["plist"]])
    else:
        die("Unknown service adapter")


def restart_and_probe(m, probe):
    service(m["service"], "stop")
    service(m["service"], "start")
    return probe_with_retries(probe)


def restore_config(m, original):
    atomic_bytes(m["conf"], original)
    cmd([m["httpd"], "-t", "-f", m["conf"]])


def deployment_root(value):
    root = pathlib.Path(value).resolve()
    if not str(root).startswith("/usr/local/"):
        die("Installation directory must be under /usr/local")
    return root


def probe_with_retries(probe, *, attempts=12, interval=1.5):
    last = None
    for attempt in range(attempts):
        try:
            return probe()
        except Exception as e:
            last = e
            if attempt + 1 < attempts:
                time.sleep(interval)
    die("HTTP health probe unavailable after Apache start: " + str(last))


def deploy(opts):
    trace("preflight")
    work = pathlib.Path(opts.work).expanduser().absolute()
    m = load_manifest(work)
    attach_diagnostics(work)
    if _DIAGNOSTIC_SESSION is not None:
        _DIAGNOSTIC_SESSION.data["target_php"] = reporting.safe_version(m.get("version"))
        _DIAGNOSTIC_SESSION.data["service"] = m["service"].get("mode", "unknown")
    platform_check(allow_root=m["service"]["mode"] == "launchd-system")
    if m["state"] != "prepared":
        die("Only a prepared build may be deployed; current state=" + m["state"])
    paths = apache_paths(argparse.Namespace(conf=m["conf"], httpd=m["httpd"], apxs=m["apxs"]))
    if paths["oldmodule"] != m["oldmodule"] or digest(paths["conf"]) != m["config_sha"]:
        die("Apache configuration changed after prepare. Re-audit and re-prepare; no changes made")
    if digest(m["oldmodule"]) != m["oldmodule_sha"]:
        die("Previously loaded PHP module changed after prepare")
    if digest(work / "candidate/libphp.so") != m["module_sha"] or digest(work / "candidate/php") != m["cli_sha"]:
        die("Staged binary checksum mismatch; refusing to deploy")
    verify_service_identity(m["service"], m["httpd"])
    trace("http-baseline")
    probe_path, probe = make_probe(opts.probe_dir, opts.probe_base, opts.host_header)
    try:
        before = probe()
        if before["php"].split(".")[:2] != m["version"].split(".")[:2]:
            die("Serving PHP minor branch differs from selected security release; refusing risky ABI migration")
        # A pinned emergency patch must never replace an equal or newer patch.
        try:
            current_version = tuple(int(part) for part in before["php"].split("."))
            target_version = tuple(int(part) for part in m["version"].split("."))
            if len(current_version) != 3 or len(target_version) != 3:
                raise ValueError("Unexpected PHP version format")
        except (ValueError, TypeError):
            die("Unrecognized live PHP version; refusing upgrade")
        if current_version >= target_version:
            die("Web server already serves an equal or newer PHP patch; refusing downgrade")
        if not isinstance(before["modules"], list):
            die("Invalid module list in baseline probe")
        missing = []
        target = deployment_root(opts.install_root or "/usr/local/libexec/php2shell-rescue")
        location = target / ("php-" + m["version"] + "-" + secrets.token_hex(6))
        if location.exists():
            die("Destination already exists")
        location.mkdir(parents=True, mode=0o755)
        mod = location / "libphp.so"
        shutil.copy2(work / "candidate/libphp.so", mod)
        shutil.copy2(work / "candidate/php", location / "php")
        if digest(mod) != m["module_sha"]:
            die("Installed module checksum mismatch")
        trace("backup")
        original = pathlib.Path(m["conf"]).read_bytes()
        backup = work / "httpd.conf.pre-upgrade"
        atomic_bytes(backup, original, mode=0o600)
        if digest(backup) != m["config_sha"]:
            die("Configuration backup checksum mismatch")
        name = paths["hit"].group("name").decode()
        new_config = change_config(original, str(mod), name, mitigation=True)
        trace("authorization")
        if not opts.yes:
            log("Cutover will STOP and START the selected Apache service; the Mac will NOT reboot.")
            if input("Type DEPLOY to continue: ") != "DEPLOY":
                die("Deployment cancelled before any Apache configuration changes")
        ps = cmd(["/bin/ps", "-axo", "command"], check=False)
        if "php-fpm" in ps.stdout:
            log("WARNING: Another PHP-FPM runtime appears to be running; this deploy does NOT patch it.")
        m.update(state="pending", backup=str(backup), deployed_module=str(mod),
                 deployed_module_sha=m["module_sha"], old_http_php=before["php"],
                 before_modules=before["modules"], before_upload=before["upload"],
                 pending_at=now(), pending_config_sha=digest_bytes(new_config))
        save_manifest(work, m)
        log("Backup complete; applying temporary Apache configuration")
        config_written = False
        service_interrupt_attempted = False
        try:
            trace("apache-configuration")
            atomic_bytes(m["conf"], new_config)
            config_written = True
            cmd([m["httpd"], "-t", "-f", m["conf"]])
            service_interrupt_attempted = True
            trace("apache-restart")
            after = restart_and_probe(m, probe)
            trace("http-verification")
            if after["php"] != m["version"]:
                die(f"Live Apache reports PHP {after['php']!r}, expected {m['version']}")
            if after["upload"] not in ("", "0"):
                die("session.upload_progress.enabled remains ON in live Apache; mitigation check failed")
            missing = sorted(set(before["modules"]) - set(after["modules"]))
            if missing:
                die("Required extensions missing after cutover: " + ", ".join(missing))
            m.update(state="deployed", deployed_at=now(), config_deployed_sha=digest(m["conf"]),
                     new_http_php=after["php"], after_modules=after["modules"])
            save_manifest(work, m)
            log("SUCCESS: Apache is serving PHP " + after["php"] + "; upload-progress mitigation OFF")
            log("Retained original module and configuration backup under " + str(work))
        except BaseException as exc:
            log("CUTOVER FAILED: " + str(exc))
            if config_written:
                try:
                    trace("automatic-rollback")
                    log("RESTORING PREVIOUS APACHE CONFIGURATION" +
                        (" AND RESTARTING SERVICE" if service_interrupt_attempted else " (SERVICE UNTOUCHED)"))
                    restore_config(m, original)
                    if service_interrupt_attempted:
                        reverted = restart_and_probe(m, probe)
                        if reverted["php"] != before["php"]:
                            die("Rollback served unexpected PHP version")
                    m.update(state="rolled_back", rollback_at=now(),
                             rollback_verified=service_interrupt_attempted)
                    save_manifest(work, m)
                    log("CONFIGURATION RESTORED. WARNING: original PHP may still be vulnerable!")
                except Exception as rollback_exc:
                    m.update(state="pending", rollback_error=str(rollback_exc))
                    save_manifest(work, m)
                    die("ROLLBACK UNVERIFIED: " + str(rollback_exc) + "; manual attention required immediately")
            else:
                m.update(state="rolled_back", rollback_at=now())
                save_manifest(work, m)
            die("Deployment did not complete: " + str(exc))
    finally:
        try:
            probe_path.unlink()
        except FileNotFoundError:
            pass


def rollback(opts):
    trace("manual-rollback")
    work = pathlib.Path(opts.work).expanduser().absolute()
    m = load_manifest(work)
    attach_diagnostics(work)
    if _DIAGNOSTIC_SESSION is not None:
        _DIAGNOSTIC_SESSION.data["target_php"] = reporting.safe_version(m.get("version"))
        _DIAGNOSTIC_SESSION.data["service"] = m["service"].get("mode", "unknown")
    platform_check(allow_root=m["service"]["mode"] == "launchd-system")
    if m["state"] not in ("deployed", "pending"):
        die("Rollback available only after deployment or interrupted cutover")
    verify_service_identity(m["service"], m["httpd"])
    original = pathlib.Path(m["backup"]).read_bytes()
    if digest_bytes(original) != m["config_sha"]:
        die("Backup was modified; manual recovery required")
    current = pathlib.Path(m["conf"]).read_bytes()
    expected = m.get("config_deployed_sha")
    if expected and digest_bytes(current) != expected:
        die("Live configuration changed since deploy; do not overwrite administrator edits")
    if not expected and digest_bytes(current) not in (m["config_sha"], m.get("pending_config_sha")):
        die("Configuration differs from both saved old and prepared new state; manual recovery required")
    if not opts.yes and input("Rollback to the former (possibly VULNERABLE) PHP version? Type ROLLBACK: ") != "ROLLBACK":
        die("Rollback cancelled")
    probe_path, probe = make_probe(opts.probe_dir, opts.probe_base, opts.host_header)
    try:
        restore_config(m, original)
        after = restart_and_probe(m, probe)
        if after["php"] != m["old_http_php"]:
            die("Rollback Apache PHP version check failed. MANUAL INTERVENTION REQUIRED")
        m.update(state="rolled_back", rollback_at=now(), rollback_verified=True)
        save_manifest(work, m)
        log("Rollback complete. WARNING: former PHP may be affected by PHP2Shell.")
    finally:
        probe_path.unlink(missing_ok=True)


def status(opts):
    trace("manifest")
    work = pathlib.Path(opts.work).expanduser().absolute()
    m = load_manifest(work)
    attach_diagnostics(work)
    log("WORK STATUS: " + m["state"])
    log("TARGET PHP: " + m["version"])
    log("SERVICE MODE: " + m["service"]["mode"])
    log("APACHE CONFIG MATCHES PREPARED: " + str(digest(m["conf"]) == m["config_sha"]))
    if m.get("config_deployed_sha"):
        log("APACHE CONFIG MATCHES DEPLOYED: " + str(digest(m["conf"]) == m["config_deployed_sha"]))
    log("NOTE: Status does not establish which PHP is serving HTTP requests")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)
    def apache_args(p):
        p.add_argument("--conf", default="/usr/local/etc/httpd/httpd.conf")
        p.add_argument("--httpd", default="/usr/local/opt/httpd/bin/httpd")
        p.add_argument("--apxs", default="/usr/local/opt/httpd/bin/apxs")
    a = sub.add_parser("audit", help="Inspect environment; assess preliminary readiness and invite beta reports")
    apache_args(a)
    a.add_argument("--service", choices=["brew-user", "launchd-system"], default="brew-user")
    a.add_argument("--launchd-plist", help="Explicit system LaunchDaemon plist if using --service launchd-system")
    p = sub.add_parser("prepare", help="Build a verified candidate; no live changes")
    apache_args(p)
    p.add_argument("--version", choices=sorted(RELEASES), default="8.5.12")
    p.add_argument("--work", required=True, help="New, user-owned working directory")
    p.add_argument("--configure-file", help="Reviewed PHP configure arguments (one per line)")
    p.add_argument("--jobs", type=int, default=1)
    p.add_argument("--service", choices=["brew-user", "launchd-system"], default="brew-user")
    p.add_argument("--launchd-plist", help="Explicit system LaunchDaemon plist for Apache")
    st = sub.add_parser("status", help="Read private manifest state; no server changes")
    st.add_argument("--work", required=True)
    for name in ("deploy", "rollback"):
        d = sub.add_parser(name, help="Cut over Apache or restore previous configuration")
        d.add_argument("--work", required=True)
        d.add_argument("--probe-dir", required=True, help="Existing PHP-enabled Apache document directory")
        d.add_argument("--probe-base", required=True, help="HTTP URL reaching that directory via 127.0.0.1")
        d.add_argument("--host-header", help="Optional matching virtual-host name")
        d.add_argument("--yes", action="store_true", help="Explicitly accept service downtime / rollback warning")
        if name == "deploy":
            d.add_argument("--install-root", default="/usr/local/libexec/php2shell-rescue")
    reporter = sub.add_parser("report", help="Review exact sanitized report, then optionally send it over HTTPS")
    reporter.add_argument("--work", help="Use diagnostics from a particular prepared/deployed work directory")
    reporter.add_argument("--endpoint", default=reporting.DEFAULT_ENDPOINT,
                          help="HTTPS URL of standalone report receiver")
    opts = parser.parse_args(argv)
    if opts.action == "report":
        try:
            reporting.report_command(opts.work, opts.endpoint)
            return 0
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
            print("REPORT ERROR: " + str(exc), file=sys.stderr)
            print("Nothing was removed; try again after checking the endpoint.", file=sys.stderr)
            return 1
    global _DIAGNOSTIC_SESSION
    _DIAGNOSTIC_SESSION = reporting.DiagnosticSession(
        opts.action, target_php=getattr(opts, "version", None),
        service=getattr(opts, "service", None), work=getattr(opts, "work", None))
    try:
        if opts.action == "audit":
            preliminary_candidate = doctor(opts)
            # The fixed receiver schema has no readiness field. For beta
            # triage, a completed audit with compatibility warnings is a
            # diagnostic failure, but the audit command itself returns zero.
            if preliminary_candidate:
                _DIAGNOSTIC_SESSION.finish(True)
            else:
                _DIAGNOSTIC_SESSION.finish(False, "Audit readiness manual review: configuration unsupported")
            return 0
        {"prepare": prepare, "deploy": deploy,
         "rollback": rollback, "status": status}[opts.action](opts)
        _DIAGNOSTIC_SESSION.finish(True)
        return 0
    except KeyboardInterrupt:
        _DIAGNOSTIC_SESSION.finish(False, "User cancelled operation")
        if opts.action == "audit":
            audit_summary("incomplete", ["The audit was interrupted before its checks completed."])
        print("\nOperation interrupted. Inspect server state before taking further action.", file=sys.stderr)
        return 130
    except (RescueError, OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as exc:
        _DIAGNOSTIC_SESSION.finish(False, str(exc))
        print("ERROR: " + str(exc), file=sys.stderr)
        if opts.action == "audit":
            kind = "unsupported" if isinstance(exc, RescueError) else "incomplete"
            audit_summary(kind, ["See the reported error above; correct the issue before proceeding."])
        else:
            print("Optional beta report: python3 php2shell_rescue.py report"
                  + (" --work " + str(opts.work) if getattr(opts, "work", None) else ""), file=sys.stderr)
        return 1
    finally:
        if opts.action == "audit":
            audit_report_invitation()
        _DIAGNOSTIC_SESSION = None


if __name__ == "__main__":
    sys.exit(main())

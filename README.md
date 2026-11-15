# PHP2SHELL RESCUE

**DOCUMENT:** Project README  
**RELEASE:** 0.3.4-beta  
**RELEASE DATE:** November 14, 2026  
**AUTHOR:** Steven Stromer  
**COPYRIGHT:** © 2026 Steven Stromer  
**LICENSE:** MIT (see `LICENSE`)

**EXPERIMENTAL SOFTWARE — READ `BETA_NOTICE.md` BEFORE USE**

---

## INTRODUCTION AND BETA STATUS
PHP2Shell Rescue is a guarded emergency PHP source installer for an unusual
situation: an older Intel Mac continues to run a dependable Apache/PHP server,
but Homebrew can no longer build or upgrade one of PHP's dependencies. It
builds a selected patched PHP release from authenticated upstream source,
stages a replacement `mod_php` module, and offers a controlled switchover with
an automatic *attempt* to roll back if validation fails.

**Version 0.3.4 updates the documentation, packaging, and release identifiers;
it does not change the installation or reporting procedures.** The original PHP
replacement procedure succeeded manually on the
development system, but the automated deployment and rollback paths have not
been validated on physical test systems. Do not execute `deploy` on a server
you cannot afford to interrupt. Before proceeding, inspect the source, confirm
the results of the read-only audit, maintain verified backups, and establish a
recovery method independent of Apache. Automatic rollback is not guaranteed.
See [BETA_NOTICE.md](BETA_NOTICE.md) for the full operational warning and
[BETA_REPORTING.md](BETA_REPORTING.md) for the optional reporting policy.

---

## SECURITY BACKGROUND
On October 21, 2026, PHP published security releases 8.2.35, 8.3.36, 8.4.27,
and 8.5.12 for CVE-2026-109618 and CVE-2026-109619. The PHP security team
described possible pre-authentication remote code execution and identified
`mod_php` as particularly exposed. On October 23, PHP separately recommended
disabling `session.upload_progress.enabled` until the next maintenance release
in connection with CVE-2026-115560. **Disabling upload progress alone does not
fix PHP2Shell.** Refer to the upstream advisories listed below.

If immediate patching is impossible, reduce external exposure and consult
PHP's temporary mitigation guidance. Supported PHP releases are preferable
to unsupported branches. Linux, FreeBSD, Windows, containerized deployments,
and vendor-maintained PHP installations should use their own supported patch
channels rather than this macOS utility.

---

## SUPPORTED CONFIGURATIONS AND EXCLUSIONS
Automatic deployment is intentionally limited to a single recognizable
Homebrew Apache installation on a **native Intel Mac (`x86_64`)**, with Xcode
Command Line Tools available. The supported environment requires:

- **Apache:** Homebrew `httpd` under `/usr/local`, with one direct PHP
  `LoadModule` directive in the main configuration. The directive must use
  an absolute module path, and the active default configuration must be the
  configuration file selected for the operation.
- **Service:** `brew services` under the current non-root user, or an
  explicitly selected macOS system LaunchDaemon whose `ProgramArguments`
  directly execute the same Homebrew `httpd` binary.
- **PHP:** a live `mod_php` installation already on the same **major.minor**
  branch as the requested patched release. Only the four pinned versions
  identified above are accepted; branch migration is not supported.
- **Verification:** a writable PHP-enabled document directory reachable
  using a loopback-only HTTP URL. The utility creates and removes a temporary,
  randomly named PHP probe; virtual hosts may require `--host-header`.

**Not supported for automatic deployment:** Apple's `/usr/sbin/httpd`;
PHP-FPM/FastCGI-only environments; HTTPS-only loopback probes; multiple
Apache instances or PHP modules; multiple PHP `LoadModule` directives;
manually launched Apache; Apache managed through wrapper processes or
`apachectl`; PHP branch migrations; Docker; Linux; and Apple Silicon.

The original case study used a custom system service, rather than a Homebrew
user agent. The `launchd-system` adapter targets direct-`httpd` system
LaunchDaemons, but has not yet been tested in a real automated cutover.

---

## INCLUDED FILES
The release contains the installer, a separate opt-in reporter, documentation,
a receiver template, and automated tests. The most important files are:

- `php2shell_rescue.py` — Python 3.9+ installer; standard library only.
- `php2shell_reporting.py` — sanitized local diagnostics and optional HTTPS
  submission.
- `BETA_NOTICE.md` — operational risks, recovery caveats, privacy, and warranty
  information; **read before installation**.
- `BETA_REPORTING.md` — local diagnostic records, submission, and privacy.
- `LICENSE` — standard MIT License and full warranty disclaimer.
- `configure-args.example.txt` — example of custom configure arguments.
- `receiver/php2shell_report.php` — standalone PHP receiver template, not
  automatically installed or activated by the utility.
- `receiver/DEPLOY_RECEIVER.md` — receiving-server deployment instructions.
- `tests/test_rescue.py` — simulated deployment, failure, and rollback tests.
- `tests/test_reporting.py` — reporting privacy and downgrade safeguards.
- `tests/test_audit.py` — audit-readiness classification tests.
- `SHA256SUMS.txt` — checksums for selected package files.

The receiver is included for inspection or separate deployment by a publisher;
it is **not** part of the end-user PHP upgrade procedure.

---

## PREREQUISITES AND READ-ONLY AUDIT
A **recent, verified, restorable backup** and independent administrative access
are prerequisites for any deployment attempt. The script never reboots the
computer, but `deploy` and `rollback` deliberately stop and start the selected
Apache service, causing service interruption. It neither upgrades Homebrew
nor overwrites the existing PHP module file.

The utility invokes `curl`, `tar`, `make`, `otool`, and the Xcode toolchain; it
requires Python 3.9 or later and pre-existing compatible headers and libraries.
It does not install missing dependencies. Build environments may require
`CPPFLAGS`, `LDFLAGS`, `LIBS`, `PKG_CONFIG_PATH`, or `CFLAGS` to select the
correct libraries. Begin by checking Python and performing a read-only audit:

    python3 --version
    python3 php2shell_rescue.py audit

The audit reports a preliminary configuration assessment:
`PRELIMINARY CANDIDATE`, `MANUAL REVIEW REQUIRED`, or
`UNSUPPORTED CONFIGURATION`. A promising assessment confirms only that initial
Intel, Apache/`mod_php`, service, and tool checks look plausible; it does
**not** establish library ABI compatibility, disk capacity, extension behavior,
or that deployment will succeed. An unsupported machine causes an audit error.
A completed audit needing manual review may return exit status 0 while its
structured diagnostic result records `CONFIGURATION_UNSUPPORTED` for beta
triage. Audit readiness is **not** deployment approval.

For a direct-`httpd` **system LaunchDaemon**, identify the service explicitly
rather than relying on the default Homebrew user-service check:

    python3 php2shell_rescue.py audit \
        --service launchd-system \
        --launchd-plist /Library/LaunchDaemons/YOUR-HTTPD.plist

Every audit, including an unsuccessful one, offers the opportunity to submit
an optional diagnostic report. No information is transmitted until the user
runs the `report` command, reviews the JSON payload, and types `SEND`.

---

## PREPARING AND REVIEWING THE PHP BUILD
After reviewing the audit output, prepare a candidate for the matching
installed PHP branch. The following example prepares PHP 8.5.12:

    python3 php2shell_rescue.py prepare \
        --version 8.5.12 \
        --work "$HOME/php2shell-work-8.5.12"

For an existing PHP 8.4, 8.3, or 8.2 installation, select the corresponding
pinned patch version: `8.4.27`, `8.3.36`, or `8.2.35`. The tool accepts only
the explicitly pinned archives and checks the upstream download against its
bundled SHA-256 value. For a custom build, prepare and personally review a
machine-specific options file with one configure argument per line, then add
`--configure-file configure-args.txt`. The tool overrides `--prefix`,
`--with-apxs2`, and CLI/FPM selection to keep the candidate isolated.

**Before deployment**, inspect `configure.log`, `make.log`,
`configure-arguments.txt`, the new CLI's version output, and the candidate
module's `otool -L` dependencies. Review the existing `php.ini` and installed
extensions. The live HTTP test checks the previous and new extension-name
sets, but missing or incompatible third-party extensions may prevent the new
module from loading or functioning correctly. The utility does **not** rebuild
Imagick, PECL extensions, or other dependencies, and does not automatically
patch a separately installed CLI PHP or PHP-FPM server.

---

## DEPLOYMENT WITH A HOMEBREW USER SERVICE
For a PHP-enabled site whose document root is reachable locally on port 8080,
use a command of this form:

    python3 php2shell_rescue.py deploy \
        --work "$HOME/php2shell-work-8.5.12" \
        --probe-dir "/path/to/site/document-root" \
        --probe-base "http://127.0.0.1:8080/"

**Replace the example document directory and port** with values for the
actual local Apache installation. Where a virtual host needs a `Host` header,
add `--host-header your-local-vhost-name`. If the probe is exposed through a
subdirectory, `--probe-base` must refer to that precise directory and end in
`/`. The probe must be reachable by HTTP on loopback.

Before cutover, the utility checks that the running PHP branch matches the
candidate, backs up the Apache configuration, installs a versioned replacement
module without overwriting the original, applies an Apache-side
`php_admin_flag session.upload_progress.enabled Off` mitigation, and runs
`httpd -t`. It requires the administrator to type `DEPLOY` before altering
the live configuration. It then stops and starts the selected Homebrew user
Apache service and sends an actual HTTP request to verify the requested PHP
version, the `apache2handler` SAPI, previously loaded extension names, and
an upload-progress mitigation value of `0`.

If a post-cutover verification check fails, the utility attempts to restore
the previous configuration and restart Apache. **Neither service recovery nor
restoration of a secure PHP version is guaranteed.** The prior PHP version may
remain vulnerable after rollback. A failed rollback requires immediate manual
investigation; the private manifest and configuration backup are retained.

---

## DEPLOYMENT WITH A SYSTEM LAUNCHDAEMON
A direct-`httpd` system LaunchDaemon requires root privileges for the actual
cutover, but the PHP build should still be prepared by the **normal
administrator user**. Specify the service adapter while preparing:

    python3 php2shell_rescue.py prepare \
        --version 8.5.12 \
        --work "$HOME/php2shell-work-8.5.12" \
        --service launchd-system \
        --launchd-plist /Library/LaunchDaemons/EXAMPLE.apache.plist

The plist must exist directly inside `/Library/LaunchDaemons` and execute the
configured Homebrew `httpd` binary without a wrapper. The tool records the
plist's hash and label and refuses to proceed if either changes. Service
management uses `launchctl bootout system` and `launchctl bootstrap system`;
**it never performs a whole-system reboot.**

For cutover, use `sudo` only for `deploy`, and specify an **absolute** working
directory path rather than `$HOME`, which may differ under `sudo`:

    sudo python3 php2shell_rescue.py deploy \
        --work /ABSOLUTE/PATH/TO/php2shell-work-8.5.12 \
        --probe-dir /ABSOLUTE/PATH/TO/document-root \
        --probe-base http://127.0.0.1:8080/

**This adapter has not been validated through a live automated LaunchDaemon
cutover.** Carefully inspect the plist's `ProgramArguments`, service
identity, Apache configuration, and available recovery procedures before
considering deployment on a public-facing host.

---

## ROLLBACK AND INTERRUPTED-RUN RECOVERY
If a previously verified deployment develops another problem, `rollback`
restores the saved Apache configuration, restarts the selected service, and
checks whether PHP again reports the prior version:

    python3 php2shell_rescue.py rollback \
        --work "$HOME/php2shell-work-8.5.12" \
        --probe-dir /path/to/site/document-root \
        --probe-base http://127.0.0.1:8080/

For a system LaunchDaemon, use `sudo` for rollback too and supply absolute
paths. If Apache cannot start, or the operation is interrupted, investigate
`manifest.json` and `httpd.conf.pre-upgrade` in the private working directory.
Those files are necessary for manual recovery and should not be deleted
until the installation is known to be stable. **Returning to an older,
vulnerable PHP version is an availability measure, not a security fix.**

To inspect a work directory without changing Apache or other services, use:

    python3 php2shell_rescue.py status \
        --work /ABSOLUTE/PATH/TO/work-directory

A `pending` state may indicate an interrupted deployment or incomplete
rollback. Inspect the saved configuration and actual Apache/PHP state before
attempting further changes. Never publish private manifests, configuration
backups, or unreviewed server logs.

---

## VOLUNTARY DIAGNOSTIC REPORTING
Version 0.3 provides opt-in reporting through `php2shell_reporting.py` and a
separate PHP receiver. After `audit`, `prepare`, `deploy`, `rollback`, or
`status`, a user may inspect and submit a local, structured diagnostic report:

    python3 php2shell_rescue.py report

For work-directory diagnostics, particularly after operations involving
`sudo` and a system LaunchDaemon, specify the existing absolute work path:

    python3 php2shell_rescue.py report \
        --work /ABSOLUTE/PATH/TO/WORK

The utility displays the exact allowlisted JSON data and waits for the user
to type `SEND` before making an HTTPS POST. A tracking ID confirms receipt;
failed uploads leave the original local record available. No operation sends
a report automatically. Reports contain predefined results, platform/version
information, and aggregate error categories rather than raw build logs,
configurations, usernames, hostnames, addresses, or unfiltered command output.
The receiving server may nevertheless log the connecting public IP address.

The bundled `receiver/php2shell_report.php` is a separately deployed template;
its presence in the ZIP does not activate reporting on any server. For exact
report fields, local storage, readiness classifications, privacy, retention,
and submission limits, see `BETA_REPORTING.md`. Administrators should also
review `receiver/DEPLOY_RECEIVER.md` before configuring a receiving endpoint.

---

## LIMITATIONS, TESTING, AND SAFETY
Only one Apache instance and one `mod_php` module are verified by the
installer. PHP-FPM or CLI PHP can remain vulnerable independently. The HTTP
probe checks a selected endpoint but does not cover every virtual host or
exercise complete application functionality. Extension names are compared,
but application behavior, database connections, extension compatibility,
file permissions, and representative workloads still need separate testing.

Service stop/start operations can fail for reasons outside the utility's
control, including filesystem, permissions, or `launchd` problems. Rollback
can fail for the same reasons. The installed Apache `php_admin_flag` disables
session upload progress and may affect applications that require that feature;
it does not address unrelated operating-system or dependency vulnerabilities.
Never assume that any successful single HTTP check proves an entire server is
secure or fully compatible.

The application has been tested with automated unit and simulated cutover
tests, including the audit-readiness classifications. **The packaged application
was not compiled and deployed through a real automated Intel Mac cutover in
the release session.** Spare-machine testing with representative libraries,
extensions, Apache configuration, and service management remains necessary.
Run the packaged tests from the project directory with:

    python3 -m unittest discover -s tests -v

Do not publish audit output, private manifests, compiler logs, HTTP access
logs, Apache backups, or configuration files without reviewing them for
usernames, local paths, domains, ports, addresses, and other sensitive data.

---

## REPOSITORY, RELEASES, AND FEEDBACK
This repository provides the project's source code, documentation, and tests.
The `README.md` shown on GitHub is also the README included with the release
package; there is no separate GitHub-only version. Start with this file and
[BETA_NOTICE.md](BETA_NOTICE.md), then consult
[BETA_REPORTING.md](BETA_REPORTING.md) before using voluntary reporting.

When GitHub release assets are provided, use the explicitly attached,
versioned beta archive and its accompanying SHA-256 checksum instead of
assuming GitHub's automatically generated source-code ZIP is the same as the
tested distribution. Verify the checksum before extracting or executing the
archive. Official project background and the original technical article are
available at `https://code.stevenstromer.com/`.

If the repository's **Issues** feature is enabled, it may be used for bug
reports or suggestions. Include the utility version, the attempted operation,
and only information you have personally checked for privacy. **Do not post
raw build logs, server configurations, credentials, full diagnostic records,
or private paths publicly.** Submitting an issue or diagnostic report does not
guarantee a response or individual technical support. This project is
maintained independently; GitHub access is not required to run the utility.

---

## LICENSE AND DISTRIBUTION
Copyright © 2026 Steven Stromer. PHP2Shell Rescue and the accompanying
source code and documentation are provided under the **MIT License**; read
the unmodified `LICENSE` for the complete terms and warranty disclaimer. The
software is supplied **AS IS, without warranty**, and the beta is not
production-certified. `BETA_NOTICE.md` explains operational risks, recovery
limits, and privacy responsibilities and must accompany the software.

The installer retrieves PHP source separately from the PHP project when
requested; no upstream PHP source archive is distributed here. Upstream PHP
code is covered by its own license and maintenance obligations.

---

## REFERENCES
- PHP security advisory (October 21, 2026):
  https://www.php.net/archive/2026.php#2026-10-21-5
- PHP session-upload advisory (October 23, 2026):
  https://www.php.net/archive/2026.php#2026-10-23-1
- PHP source releases and checksums:
  https://www.php.net/downloads.php
- Homebrew support tiers:
  https://docs.brew.sh/Support-Tiers

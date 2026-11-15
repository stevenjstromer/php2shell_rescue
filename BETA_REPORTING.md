# PHP2SHELL RESCUE

**DOCUMENT:** Beta Reporting and Local Diagnostics  
**RELEASE:** 0.3.4-beta  
**RELEASE DATE:** November 14, 2026  
**AUTHOR:** Steven Stromer  
**COPYRIGHT:** © 2026 Steven Stromer  
**LICENSE:** MIT (see `LICENSE`)

**VOLUNTARY REPORTING — REVIEW ALL INFORMATION BEFORE SUBMISSION**

---

## SUBMITTING A DIAGNOSTIC REPORT
After any `audit`, `prepare`, `deploy`, `rollback`, or `status` command, an
administrator may review and voluntarily submit the local diagnostic report
using:

    python3 php2shell_rescue.py report

If the operation was run with `sudo` under the system LaunchDaemon mode, read
the report from the **work directory** as the normal administrator user:

    python3 php2shell_rescue.py report --work /ABSOLUTE/PATH/TO/WORK

The reporter prints the **exact JSON payload** that will be transmitted. Type
the word `SEND` to approve the HTTPS upload. Any other response cancels without
network access. A successful receipt returns a tracking ID of the form
`P2S-0123456789ab`. If the upload fails, the original local diagnostic record
remains available and the command can be retried.

---

## REPORTING ENDPOINT
The published endpoint is
`https://code.stevenstromer.com/public/uploaders/php2shell_report.php`. If it is
unavailable, submission fails without deleting the local record. The bundled
receiver file is only a template and does not configure the website; a receiver
must be separately configured and tested before submissions can succeed.

---

## AUDIT READINESS AND REPORTING
Every `audit`, including one that fails to recognize a machine, invites
voluntary report submission. The terminal assessment has three outcomes:
`PRELIMINARY CANDIDATE`, `MANUAL REVIEW REQUIRED`, and
`UNSUPPORTED CONFIGURATION` (or `INCOMPLETE` for an interrupted check). A completed audit
needing manual review returns an exit code of 0 because the audit itself
finished; its diagnostic `result` is `failure` and its generic `error_code` is
`CONFIGURATION_UNSUPPORTED` to make it visible during triage. No new fields are
transmitted, so these reports remain compatible with the existing receiver
schema. These assessments do **not** determine that building or deploying PHP
would succeed or be safe on the host.

---

## LOCAL DIAGNOSTIC INFORMATION
Automatic logging stores fixed stages, the command name and result, the PHP
version selected, broad OS version and architecture, selected service adapter,
generic failure code, and counts of compiler/linker error categories. It stores
records under `~/.php2shell-rescue/latest.json` (owner-only) and in a work
directory's `diagnostics.json` after that directory has been validated.

---

## EXCLUDED INFORMATION AND FILE SAFETY
The report excludes raw stdout/stderr and whole compilation logs, paths,
usernames, machine names, IP addresses, virtual-host names, Apache/PHP
configuration contents, credentials, tokens, and free-form messages. Diagnostic
classification reads the local `configure.log` and `make.log` but sends only
**predefined category counts**, never the original lines. The local logs, work
manifest, Apache backups, and other files can still contain secrets: **never
upload or publish them without personal review.**

---

## PRIVACY AND DATA RETENTION
A session-specific random identifier distinguishes reports without creating a
permanent identifier for a computer. The report's contents are displayed in full
before submission. The receiving hosting service can nevertheless observe the
connecting IP address and may log it separately from the report. Uploaded report
files are stored in a private directory with a 30-day target retention policy
and purged when new submissions arrive. Without new traffic, cleanup is not
guaranteed unless a scheduled cleanup job is configured.

---

## REPORTING LIMITS AND SAFETY
Reporting is an entirely separate user action; no installation error causes an
automatic upload. The standalone receiver does not depend on the main site
framework. It accepts only fixed structured fields and applies size, storage,
and rate limits. Logging errors do not block an urgently needed security upgrade
or rollback. If local logging could not save a diagnostic record, `report` may
have no usable record to submit.

Public beta testing remains experimental. Administrators should back up their
systems, confirm independent administrative access, anticipate possible Apache
downtime, and never assume that automatic rollback will succeed. Reporting does
not provide support guarantees or prove that an installation is secure. Actual
Apache/PHP functionality requires independent verification.

---

## LICENSE AND RELATED DOCUMENTATION
PHP2Shell Rescue is distributed under the MIT License. See `LICENSE` for the
complete warranty and liability disclaimer and `BETA_NOTICE.md` for
participation risks and privacy details. These documents accompany the software
and should be reviewed before attempting installation or deployment.

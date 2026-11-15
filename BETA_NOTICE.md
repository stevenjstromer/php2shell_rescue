# PHP2SHELL RESCUE

**DOCUMENT:** Public Beta Notice  
**RELEASE:** 0.3.4-beta  
**RELEASE DATE:** November 14, 2026  
**AUTHOR:** Steven Stromer  
**COPYRIGHT:** © 2026 Steven Stromer  
**LICENSE:** MIT (see `LICENSE`)

**EXPERIMENTAL SOFTWARE — PLEASE READ BEFORE USE**

---

## EXPERIMENTAL SOFTWARE
PHP2Shell Rescue is experimental software intended to assist experienced
administrators in applying emergency PHP security updates to older Intel-based
Macs. It is not a production-certified installation or security-maintenance
tool, and it has not been validated across the range of hardware, macOS
versions, dependencies, and Apache configurations that prospective users may
encounter. Although the underlying PHP replacement procedure was performed
successfully on the original development system, the automated deployment and
rollback operations have not been validated on physical test systems. Successful
automated testing does not establish that the utility will operate safely in
other environments.

---

## INSTALLATION AND OPERATIONAL RISKS
The utility compiles PHP against existing system libraries and attempts to
preserve the relevant Apache configuration and PHP extensions. Preparation can
consume substantial processing resources, and deployment or rollback
deliberately stops and restarts the selected Apache service. Websites and
dependent applications may become temporarily unavailable. Missing dependencies,
incompatible extensions, unexpected configurations, or installation failures may
cause extended downtime or require manual intervention. Although the utility
attempts to restore the previous configuration when deployment verification
fails, successful rollback cannot be guaranteed. Restoring an earlier PHP
installation may also restore the security vulnerabilities that prompted the
upgrade.

---

## BACKUP AND RECOVERY REQUIREMENTS
**DO NOT USE THIS BETA ON A SERVER YOU CANNOT AFFORD TO INTERRUPT.** Before
attempting deployment, administrators should maintain verified, restorable
backups, including Apache configuration files and related application data, and
ensure that independent administrative access remains available if the web
server becomes unavailable. Users should review the source code and accompanying
documentation and establish an appropriate recovery procedure before making
changes to a working installation. The utility does not reboot the computer, but
it may interrupt Apache and services that depend upon it.

---

## SUPPORTED CONFIGURATIONS AND LIMITATIONS
PHP2Shell Rescue is intentionally restricted to supported Homebrew
Apache/mod_php configurations on native Intel Macs. It does not provide a
general-purpose PHP upgrade mechanism, nor does it secure unrelated PHP
installations, PHP-FPM services, command-line environments, or the operating
system. A successful installation or HTTP verification test is not a guarantee
of complete application compatibility or server security. Administrators remain
responsible for assessing the suitability of the utility for their systems and
for applying any additional security updates or mitigations that may be
necessary.

---

## VOLUNTARY DIAGNOSTIC REPORTING
The public beta includes an optional diagnostic reporting facility intended to
help identify compatibility problems and improve subsequent releases. Reports
contain a limited set of predefined operation results, software and platform
information, and aggregate error categories. Raw compiler logs, configuration
files, filesystem paths, usernames, hostnames, authentication credentials, and
network addresses are not included in the structured report. Before
transmission, the reporting utility displays the exact JSON content and requires
explicit confirmation by entering `SEND`. No diagnostic report is transmitted
automatically as a consequence of running an audit, preparing an installation,
deploying PHP, or performing a rollback.

---

## PRIVACY, DATA RETENTION, AND SUPPORT
Submitted diagnostic reports are held in private server storage with a 30-day
cleanup target, although cleanup is opportunistic and an exact deletion date
cannot be guaranteed. The receiving web server and hosting provider may
independently record public IP addresses and other request metadata in their
access logs, which may be subject to different retention policies. Users should
inspect any additional diagnostic files, logs, or configurations before sharing
them separately. Participation in reporting is voluntary, and no individual
technical support, response, or corrective action is guaranteed. Additional
information is provided in `BETA_REPORTING.md`.

---

## LICENSE AND DISCLAIMER
PHP2Shell Rescue is distributed under the MIT License, Copyright © 2026 Steven
Stromer. The complete license terms are provided in the accompanying `LICENSE`
file. The software is provided **"AS IS", WITHOUT WARRANTY OF ANY KIND**,
including warranties of merchantability, fitness for a particular purpose, and
noninfringement, subject to applicable law. The author makes no guarantee of
successful installation, recovery, compatibility, or security. Users assume
responsibility for evaluating and operating the software in their own
environments. PHP source code obtained separately from php.net remains subject
to its own licensing terms.

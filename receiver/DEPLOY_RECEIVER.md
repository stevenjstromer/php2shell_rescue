# PHP2Shell Rescue v0.3.4 — standalone beta receiver

The receiver is **one standalone PHP file**. It does not include or modify the site framework, `page_builder.php`, the articles index, or a database. Testers never open the website: `python3 php2shell_rescue.py report` sends an opt-in JSON report directly by HTTPS.

## Installation — do not guess server paths

1. Establish the **actual** public document root used by `code.stevenstromer.com` on DreamHost and identify a directory **outside** that root where the web-server PHP process can write. Do not place reports under the published website or rely on a guessed `/home/...` path. Use an existing private directory, or create a dedicated folder with permission `0700` and ensure the PHP runtime can write there.
2. Open `php2shell_report.php` and replace the **single** `$privateStorageDirectory` placeholder with that verified absolute private folder. The receiver deliberately returns HTTP 503 `receiver_not_configured` until this is done. The directory must exist, must not be a symlink or inside the document root, and must not be readable by group/others.
3. Upload only `php2shell_report.php` to `public/uploaders/php2shell_report.php` under the verified website document root. Do not upload the `receiver` folder, this README, or any storage directory to the public document root. No database or site `include` files are necessary.
4. Check the direct URL `https://code.stevenstromer.com/public/uploaders/php2shell_report.php` via `curl -i`. Expected response to **GET**: HTTP **405**, JSON `{"status":"post_only"}`. If the site instead responds with its main page, a redirect, or a 404, **stop**. Inspect the site's actual `.htaccess` / URL rewrite rules before changing anything. The receiver must remain an independent direct endpoint.
5. Confirm PHP has permission to create files in the selected private directory. From an independent test system, run `python3 php2shell_rescue.py audit`, then `python3 php2shell_rescue.py report`. Review the exact JSON and type `SEND` to submit. Expected result: `Report received. Tracking ID: P2S-...`.
6. On the server, confirm that a matching `P2S-*.json` exists in the private directory and that its content contains **only** the allowlisted fields shown to the tester. Confirm that file permissions are `0600`.

**Do not publish the beta download link before step 6 succeeds.** Nothing should be added to `page_builder.php` or the article-index router merely to make the receiver work. If the URL-rewriting rules intercept direct PHP paths, review the actual rewrite configuration before adding an isolated exception.

## Operational characteristics

- Request method: POST. Content-Type: `application/json`. HTTPS is enforced by the distributed Python client; the website must serve this endpoint over HTTPS. The receiver itself cannot prove TLS when behind certain reverse proxies; configure TLS at the hosting layer.
- Strict allowlist: utility version, operation/stage results, selected PHP version, coarse OS version and CPU architecture, service type, and aggregate error **categories/counts**. Any unexpected JSON key is rejected. **Raw logs, module paths, hostnames, domains, IPs, user names, configuration files and free-form comments are never accepted** as report data.
- Report limit: 16 KiB; no binary attachments.
- Rate limits: 6 reports/hour per source address and 60 reports/hour total (simple filesystem counters). No embedded API key.
- Storage quota: 2,000 reports or 20 MiB, whichever is reached first. Reports have random, unguessable names such as `P2S-0123456789ab.json`.
- Retention: reports older than 30 days are deleted on **subsequent incoming requests**. This is opportunistic, not guaranteed timed deletion. For strict 30-day retention, later schedule a private cleanup job. The server's own HTTP access logs and hosting-provider logs have separate retention and may contain client IP addresses.
- Security: the directory must not be web-accessible. Files are created with `0600`; the receiver uses a lock file for rate limits and avoids storing IPs inside reports. Its rate-limit state contains keyed per-hour IP hashes, not literal IPs.
- Handling abuse: remove or rename the public `php2shell_report.php` to disable intake immediately, without disturbing the rest of the website. Review quota limits periodically and back up/secure the private folder in accordance with your policies.

## Reviewing incoming reports

Using existing SSH/SFTP access, list the private directory and inspect only the `P2S-*.json` files. Report IDs can be matched to a tester's command-line confirmation. There is intentionally **no** public report listing, website dashboard, email relay, or admin login in this version.

The receiver does not provide ongoing support or secure communication with a tester. If additional raw diagnostic material is needed, use a separate, specifically agreed-upon method; do not ask volunteers to post unsanitized configuration or compiler logs publicly.

## Before general release

Confirm the real DreamHost paths, direct URL/rewrite behavior, TLS, the PHP process's filesystem permissions, and operational storage behavior. Test negative cases and recovery on the actual hosting environment. Review `LICENSE` and `BETA_NOTICE.md`, and verify that the published download and its checksum match this release before directing the public here. No real hosting configuration has been inspected or changed by this package.

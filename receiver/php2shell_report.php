<?php
/**
 * PHP2Shell Rescue beta report receiver v0.3.4.
 * Standalone POST endpoint. No website framework, DB, or user sessions.
 * Set $privateStorageDirectory below to a pre-created directory OUTSIDE webroot.
 */
declare(strict_types=1);
umask(0077);

// INSTALLER MUST REPLACE THIS PLACEHOLDER BEFORE USING THIS FILE.
$privateStorageDirectory = '/REPLACE/WITH/ABSOLUTE/PRIVATE/REPORTS/DIRECTORY';

const MAX_BYTES = 16384;
const MAX_REPORT_COUNT = 2000;
const MAX_TOTAL_BYTES = 20971520;
const MAX_HOURLY_GLOBAL = 60;
const MAX_HOURLY_SOURCE = 6;
const RETENTION_SECONDS = 2592000; // 30 days, purged opportunistically.

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');

function respond(int $status, string $code, ?string $reportId = null): void {
    http_response_code($status);
    $response = ['status' => $code];
    if ($reportId !== null) {
        $response['report_id'] = $reportId;
    }
    echo json_encode($response, JSON_UNESCAPED_SLASHES);
    exit;
}

function validKeys(array $input, array $keys): bool {
    $actual = array_keys($input);
    sort($actual);
    sort($keys);
    return $actual === $keys;
}

function stringEnum($value, array $allowed): bool {
    return is_string($value) && in_array($value, $allowed, true);
}

function validTimestamp($value): bool {
    return is_string($value) && preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/D', $value) === 1;
}

function validVersion($value): bool {
    return $value === null || (is_string($value) && preg_match('/^\d{1,3}(?:\.\d{1,3}){1,3}$/D', $value) === 1);
}

function validReport($data): bool {
    if (!is_array($data) || !validKeys($data, [
        'schema', 'application', 'application_version', 'session', 'started_at',
        'finished_at', 'operation', 'result', 'stage', 'error_code', 'platform',
        'target_php', 'service', 'events', 'build_errors'
    ])) {
        return false;
    }
    if ($data['schema'] !== 1 || $data['application'] !== 'php2shell-rescue' ||
        !is_string($data['application_version']) ||
        preg_match('/^[a-zA-Z0-9.\-]{1,32}$/D', $data['application_version']) !== 1 ||
        !is_string($data['session']) ||
        preg_match('/^[a-f0-9]{24}$/D', $data['session']) !== 1 ||
        !validTimestamp($data['started_at']) || !validTimestamp($data['finished_at']) ||
        !stringEnum($data['operation'], ['audit', 'prepare', 'deploy', 'rollback', 'status']) ||
        !stringEnum($data['result'], ['success', 'failure', 'interrupted']) ||
        !stringEnum($data['stage'], [
            'initializing', 'environment', 'apache-discovery', 'service-discovery',
            'source-download', 'source-verification', 'configuration', 'compilation',
            'candidate-verification', 'manifest', 'preflight', 'http-baseline',
            'backup', 'authorization', 'apache-configuration', 'apache-restart',
            'http-verification', 'automatic-rollback', 'manual-rollback', 'complete'
        ]) ||
        !stringEnum($data['error_code'], [
            'NONE', 'REJECTED', 'COMMAND_FAILED', 'MISSING_DEPENDENCY',
            'CONFIGURE_FAILED', 'COMPILE_FAILED', 'SOURCE_INTEGRITY_FAILED',
            'CONFIGURATION_UNSUPPORTED', 'PREPARED_BUILD_INVALID',
            'RESTART_FAILED', 'HTTP_VERIFICATION_FAILED', 'ROLLBACK_UNVERIFIED',
            'USER_CANCELLED', 'INTERNAL_ERROR'
        ]) ||
        !stringEnum($data['service'], ['brew-user', 'launchd-system', 'unknown']) ||
        !validVersion($data['target_php'])) {
        return false;
    }
    $p = $data['platform'];
    if (!is_array($p) || !validKeys($p, ['os', 'version', 'architecture']) ||
        !stringEnum($p['os'], ['macOS', 'other']) ||
        !stringEnum($p['architecture'], ['x86_64', 'arm64', 'other']) ||
        !validVersion($p['version'])) {
        return false;
    }
    if (!is_array($data['events']) || count($data['events']) < 1 || count($data['events']) > 40) {
        return false;
    }
    $stages = [
        'initializing', 'environment', 'apache-discovery', 'service-discovery',
        'source-download', 'source-verification', 'configuration', 'compilation',
        'candidate-verification', 'manifest', 'preflight', 'http-baseline',
        'backup', 'authorization', 'apache-configuration', 'apache-restart',
        'http-verification', 'automatic-rollback', 'manual-rollback', 'complete'
    ];
    foreach ($data['events'] as $event) {
        if (!is_array($event) || !validKeys($event, ['stage', 'outcome']) ||
            !stringEnum($event['stage'], $stages) ||
            !stringEnum($event['outcome'], ['started', 'passed', 'failed'])) {
            return false;
        }
    }
    if (!is_array($data['build_errors']) || count($data['build_errors']) > 9) {
        return false;
    }
    $classes = [
        'missing_header', 'missing_library', 'pkg_config_dependency',
        'compiler_error', 'linker_error', 'undefined_symbol',
        'missing_command', 'configuration_error', 'other_error'
    ];
    foreach ($data['build_errors'] as $error) {
        if (!is_array($error) || !validKeys($error, ['class', 'count']) ||
            !stringEnum($error['class'], $classes) ||
            !is_int($error['count']) || $error['count'] < 1 || $error['count'] > 9999) {
            return false;
        }
    }
    return true;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    respond(405, 'post_only');
}
if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) {
    respond(415, 'json_required');
}
if (isset($_SERVER['CONTENT_LENGTH']) && (int) $_SERVER['CONTENT_LENGTH'] > MAX_BYTES) {
    respond(413, 'report_too_large');
}

$private = realpath($privateStorageDirectory);
$public = realpath($_SERVER['DOCUMENT_ROOT'] ?? '');
if ($private === false || !is_dir($private) || is_link($privateStorageDirectory) ||
    $public === false || $private === $public || strncmp($private . '/', $public . '/', strlen($public . '/')) === 0 ||
    !is_writable($private) || ((fileperms($private) & 0077) !== 0)) {
    respond(503, 'receiver_not_configured');
}

// Use read limit even when Content-Length is absent or untrusted.
$stream = fopen('php://input', 'rb');
if ($stream === false) {
    respond(400, 'missing_body');
}
$body = stream_get_contents($stream, MAX_BYTES + 1);
fclose($stream);
if ($body === false || strlen($body) > MAX_BYTES) {
    respond(413, 'report_too_large');
}
$data = json_decode($body, true, 8);
if (json_last_error() !== JSON_ERROR_NONE || !validReport($data)) {
    respond(422, 'invalid_report');
}

// Lock prevents concurrent quota or rate-limit checks from racing.
$lockFile = fopen($private . '/.receiver.lock', 'c+');
if ($lockFile === false || !flock($lockFile, LOCK_EX)) {
    respond(503, 'storage_unavailable');
}

$secretFile = $private . '/.receiver.secret';
if (!is_file($secretFile)) {
    $secret = bin2hex(random_bytes(32));
    $handle = @fopen($secretFile, 'x');
    if ($handle === false) {
        respond(503, 'storage_unavailable');
    }
    chmod($secretFile, 0600);
    fwrite($handle, $secret);
    fclose($handle);
}
$secret = file_get_contents($secretFile);
if (!is_string($secret) || strlen($secret) < 64) {
    respond(503, 'storage_unavailable');
}

$now = time();
$recordCount = 0;
$totalBytes = 0;
foreach (glob($private . '/P2S-*.json') ?: [] as $existing) {
    if (!is_file($existing) || is_link($existing)) {
        continue;
    }
    if (filemtime($existing) < $now - RETENTION_SECONDS) {
        @unlink($existing);
        continue;
    }
    $recordCount++;
    $totalBytes += filesize($existing);
}
if ($recordCount >= MAX_REPORT_COUNT || $totalBytes + strlen($body) > MAX_TOTAL_BYTES) {
    respond(503, 'report_storage_full');
}

// The IP is only used to calculate a keyed, short-lived rate-limit bucket.
// The IP and hash are not included in any saved report.
$bucket = (string) floor($now / 3600);
$sourceHash = hash_hmac('sha256', (string) ($_SERVER['REMOTE_ADDR'] ?? '') . ':' . $bucket, $secret);
$rateFile = $private . '/.rate-state.json';
$rate = is_file($rateFile) ? json_decode((string) file_get_contents($rateFile), true) : null;
if (!is_array($rate) || ($rate['bucket'] ?? null) !== $bucket || !is_array($rate['sources'] ?? null)) {
    $rate = ['bucket' => $bucket, 'global' => 0, 'sources' => []];
}
if (($rate['global'] ?? 0) >= MAX_HOURLY_GLOBAL ||
    ($rate['sources'][$sourceHash] ?? 0) >= MAX_HOURLY_SOURCE) {
    respond(429, 'rate_limited');
}

$reportId = 'P2S-' . bin2hex(random_bytes(6));
$filename = $private . '/' . $reportId . '.json';
$handle = @fopen($filename, 'x');
if ($handle === false) {
    respond(503, 'storage_unavailable');
}
chmod($filename, 0600);
$stored = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
$success = fwrite($handle, $stored);
fclose($handle);
if ($success === false || $success !== strlen($stored)) {
    @unlink($filename);
    respond(503, 'storage_unavailable');
}
$rate['global']++;
$rate['sources'][$sourceHash] = ($rate['sources'][$sourceHash] ?? 0) + 1;
$rateSaved = file_put_contents($rateFile, json_encode($rate), LOCK_EX);
if ($rateSaved === false) {
    // Fail closed rather than accepting reports without effective rate limiting.
    @unlink($filename);
    respond(503, 'storage_unavailable');
}
chmod($rateFile, 0600);
flock($lockFile, LOCK_UN);
fclose($lockFile);
respond(201, 'received', $reportId);

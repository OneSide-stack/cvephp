<?php
/**
 * ============================================================================
 *  NIMBUS ANALYTICS — Enterprise Analytics Dashboard
 * ============================================================================
 *  Single-file reference application bundled into the PHP2Shell lab image.
 *
 *  Target runtime : PHP 8.4.26 (fpm-fcgi) — pre-patch release affected by:
 *                     CVE-2026-109618  RCE via out-of-memory corruption
 *                     CVE-2026-109619  RCE via stale global state
 *                   (fixed upstream in PHP 8.4.27 / 8.5.12 / 8.3.36 / 8.2.35)
 *  Architecture   : nginx :80  →  PHP-FPM 127.0.0.1:9000  (under Supervisor)
 *  Bundle         : the complete UI — HTML + compiled Tailwind CSS + vanilla
 *                   JS — is embedded in this single file. No CDN, no external
 *                   assets: the lab works fully air-gapped.
 *
 *  The application is an intentionally realistic, functional corporate SaaS
 *  dashboard so the vulnerable runtime can be exercised and observed the way
 *  a production deployment would be.
 * ============================================================================
 */

declare(strict_types=1);

/* ============================================================ helpers === */

/** HTML-escape helper. */
function e(null|string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Deterministic pseudo-random float in [0,1) derived from a string key. */
function fkey(string $key): float
{
    return hexdec(hash('crc32b', $key)) / 4294967296.0;
}

/** Deterministic pseudo-random int in [$min,$max] derived from a string key. */
function ikey(string $key, int $min, int $max): int
{
    return (int) round($min + fkey($key) * ($max - $min));
}

/** Container / process uptime read from /proc/uptime, human formatted. */
function container_uptime(): string
{
    $raw = @file_get_contents('/proc/uptime');
    if ($raw === false) {
        return '—';
    }
    $s = (float) explode(' ', trim($raw))[0];
    $d = (int) floor($s / 86400);
    $h = (int) floor(fmod($s, 86400) / 3600);
    $m = (int) floor(fmod($s, 3600) / 60);
    if ($d > 0) {
        return sprintf('%dd %dh', $d, $h);
    }
    if ($h > 0) {
        return sprintf('%dh %dm', $h, $m);
    }
    return sprintf('%dm', $m);
}

/** Compact USD formatter: 1284302 → "$1.28M". */
function compact_usd(int|float $v): string
{
    if ($v >= 1000000) {
        return '$' . number_format($v / 1000000, 2) . 'M';
    }
    if ($v >= 1000) {
        return '$' . number_format($v / 1000, 1) . 'k';
    }
    return '$' . $v;
}

/** Diurnal traffic curve for an hour-of-day value (UTC). */
function diurnal(float $h): float
{
    return sin(2 * M_PI * ($h - 4) / 24);
}

/** ini value or a friendly placeholder. */
function ini_val(string $k): string
{
    $v = @ini_get($k);
    if ($v === false) {
        return '—';
    }
    return $v === '' ? '(empty)' : $v;
}

/** Signed % delta with ▲/▼, colored. $invert = "lower is better". */
function delta_html(float $d, bool $invert = false): string
{
    $good  = $invert ? $d <= 0 : $d >= 0;
    $cls   = $good ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400';
    $arrow = $d >= 0 ? '▲' : '▼';
    return '<span class="font-semibold ' . $cls . '">' . $arrow . ' ' . number_format(abs($d), 1) . '%</span>';
}

/* ====================================================== telemetry core === */

/** Current deterministic (per 4-second bucket) telemetry snapshot. */
function telemetry(): array
{
    $t      = time();
    $bucket = intdiv($t, 4);
    $days   = intdiv($t - 1767225600, 86400); // days since 2026-01-01 UTC
    $h      = (int) gmdate('G', $t) + ((int) gmdate('i', $t)) / 60 + ((int) gmdate('s', $t)) / 3600;
    $curve  = diurnal($h);

    return [
        'ts'              => $t,
        'iso'             => gmdate('c', $t),
        'sessions'        => (int) max(420, round(3760 + 870 * $curve + ikey("s$bucket", -140, 140))),
        'rps'             => (int) max(60, round(1910 + 640 * $curve + ikey("r$bucket", -110, 110))),
        'p95_ms'          => ikey("p$bucket", 94, 148),
        'error_rate'      => round(0.12 + fkey("e$bucket") * 0.42, 2),
        'users'           => 44600 + $days * 61 + ikey("u$days", -180, 260),
        'users_delta'     => round((fkey("ud$days") - 0.32) * 21, 1),
        'mrr'             => 1204000 + $days * 2310 + ikey("m$days", -900, 1400),
        'mrr_delta'       => round((fkey("md$days") - 0.30) * 14, 1),
        'sessions_delta'  => round((fkey("sd$bucket") - 0.38) * 11, 1),
        'p95_delta'       => round((fkey("pd$bucket") - 0.55) * 12, 1),
    ];
}

/** 24 hourly chart points ending "now". */
function series24(): array
{
    $t       = time();
    $start   = $t - 23 * 3600;
    $labels  = [];
    $revenue = [];
    $sessions = [];
    for ($i = 0; $i < 24; $i++) {
        $ti = $start + $i * 3600;
        $c  = diurnal((int) gmdate('G', $ti) + ((int) gmdate('i', $ti)) / 60);
        $labels[]   = gmdate('H:00', $ti);
        $revenue[]  = (int) max(12, round(41 + 26 * $c + ikey("rev-$ti", -5, 7) + $i * 0.35));
        $sessions[] = (int) max(420, round(3760 + 870 * $c + ikey("ses-$ti", -170, 170)));
    }
    return ['labels' => $labels, 'revenue' => $revenue, 'sessions' => $sessions];
}

/** Sparkline series (chronological) for a metric. */
function spark(string $ns, int $n, int $min, int $max): array
{
    $b   = intdiv(time(), 4);
    $out = [];
    for ($i = $n - 1; $i >= 0; $i--) {
        $out[] = ikey($ns . ($b - $i), $min, $max);
    }
    return $out;
}

/** Weekly traffic bars (thousands of requests per weekday). */
function weekly_bars(): array
{
    $wk    = intdiv(time(), 604800);
    $days  = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    $today = (int) gmdate('N') - 1;
    $vals  = [];
    for ($i = 0; $i < 7; $i++) {
        $vals[] = ikey("wk$wk-$i", 244, 468);
    }
    return ['days' => $days, 'values' => $vals, 'today' => $today];
}

/** HTTP status code distribution (must sum to 100). */
function status_codes(): array
{
    $b  = intdiv(time(), 4);
    $s5 = round(0.25 + fkey("c5$b") * 0.5, 2);
    $s4 = round(1.90 + fkey("c4$b") * 0.9, 2);
    $s3 = round(0.90 + fkey("c3$b") * 0.6, 2);
    return ['s2xx' => round(100 - $s5 - $s4 - $s3, 2), 's3xx' => $s3, 's4xx' => $s4, 's5xx' => $s5];
}

/* ============================================================= log gen === */

const LOG_TEMPLATES = [
    ['INFO',  'auth-api',     'JWT key rotation completed for tenant {tenant} (kid nimbus-{kid})'],
    ['INFO',  'billing',      'Stripe webhook burst absorbed: {n} charge.succeeded events, 0 failures'],
    ['INFO',  'worker-queue', 'Exceeded soft alert on queue depth: {q} jobs pending across 12 workers'],
    ['WARN',  'nginx',        'Upstream php-fpm:9000 response time {ms}ms above soft threshold (150ms)'],
    ['INFO',  'waf',          'Blocked {n} inbound requests matching rule sqli-942100 (SQLi probe)'],
    ['ERROR', 'payments',     '3DS challenge failed for txn tx_{tx} — retry scheduled in 90s'],
    ['INFO',  'sso',          'SAML assertion validated for IdP okta-preview (fingerprint sha256 match)'],
    ['INFO',  'deploy',       'Canary shifted to 10% of traffic — build 2026.10.{d}+nimbus.{kid}'],
    ['WARN',  'api-gateway',  'Rate limit engaged for api-key ****{k} — 429 responses issued'],
    ['INFO',  'fpm-pool',     'pool www: {n} active children, {q} idle, slowlog quiet'],
    ['ERROR', 'db-proxy',     'pgbouncer: pool pg-primary saturation 94% — shedding OLAP traffic'],
    ['INFO',  'cron',         'Warehouse ETL completed: 2.1B rows in {m}m {s}s (delta upserts {n}k)'],
    ['INFO',  'search',       'OpenSearch index reports-2026-10 merged: {n} segments → 1'],
    ['WARN',  'cdn',          'Cache hit ratio dipped to 87.2% for /assets/* (baseline 94%)'],
    ['INFO',  'audit',        'Role change applied: {tenant} admin granted billing:read (actor j.diaz)'],
    ['DEBUG', 'fpm-pool',     'request GET /index.php?api=stats executed in {ms}ms (pid {q})'],
    ['INFO',  'mailer',       'Digest batch dispatched to {n} recipients (SES warm pool us-east-1)'],
    ['ERROR', 'api-gateway',  'Upstream timeout after 60s — request trace {tx} aborted'],
];

const LOG_TENANTS = [
    'acme-corp', 'globex', 'initech', 'umbrella', 'hooli',
    'vandelay', 'stark-ind', 'wayne-ent', 'soylent', 'tyrell',
];

function trace_id(int $b): string
{
    return hash('crc32b', 'lo' . $b) . hash('crc32b', 'hi' . $b);
}

function make_log(int $b, int $ts): array
{
    $tpl     = LOG_TEMPLATES[ikey("t$b", 0, count(LOG_TEMPLATES) - 1)];
    $tenant  = LOG_TENANTS[ikey("n$b", 0, count(LOG_TENANTS) - 1)];
    $msg     = strtr($tpl[2], [
        '{tenant}' => $tenant,
        '{n}'      => (string) ikey("a$b", 3, 48),
        '{ms}'     => (string) ikey("b$b", 14, 290),
        '{q}'      => (string) ikey("c$b", 12, 640),
        '{tx}'     => substr(hash('crc32b', "tx$b"), 0, 8),
        '{kid}'    => substr(hash('crc32b', "k$b"), 0, 4),
        '{k}'      => substr(hash('crc32b', "kk$b"), 0, 4),
        '{d}'      => (string) ikey("d$b", 2, 29),
        '{m}'      => (string) ikey("e$b", 2, 14),
        '{s}'      => (string) ikey("f$b", 11, 58),
    ]);
    return [
        'id'      => 'L' . $b,
        'ts'      => $ts,
        'time'    => gmdate('H:i:s', $ts),
        'level'   => $tpl[0],
        'service' => $tpl[1],
        'msg'     => $msg,
        'trace'   => trace_id($b),
    ];
}

/** The $n most recent simulated operational log events. */
function recent_logs(int $n): array
{
    $t  = time();
    $b0 = intdiv($t, 3);
    $out = [];
    for ($i = 0; $i < $n; $i++) {
        $b = $b0 - $i;
        $out[] = make_log($b, $t - $i * 3 - ikey("j$b", 0, 2));
    }
    return $out;
}

/** Server-side render of one log row (mirrored by the JS logRow()). */
function render_log_row(array $l): void
{
    $lvl = strtolower($l['level']);
    ?>
    <tr data-id="<?= e($l['id']) ?>" data-level="<?= e($lvl) ?>"
        class="border-b border-slate-100 transition-colors hover:bg-slate-50/80 dark:border-slate-800/60 dark:hover:bg-slate-800/40">
      <td class="whitespace-nowrap px-3 py-2.5 font-mono text-xs text-slate-500 dark:text-slate-400"><?= e($l['time']) ?></td>
      <td class="whitespace-nowrap px-3 py-2.5"><span class="lvl lvl-<?= e($lvl) ?>"><?= e($l['level']) ?></span></td>
      <td class="whitespace-nowrap px-3 py-2.5 font-mono text-xs font-medium text-indigo-600 dark:text-indigo-400"><?= e($l['service']) ?></td>
      <td class="px-3 py-2.5 text-xs text-slate-600 dark:text-slate-300"><?= e($l['msg']) ?></td>
      <td class="whitespace-nowrap px-3 py-2.5 font-mono text-[11px] text-slate-400 dark:text-slate-500"><?= e($l['trace']) ?></td>
    </tr>
    <?php
}

/* ============================================================== charts === */

/** Inline SVG sparkline (112×32 viewBox) as a string. */
function svg_spark(array $vals): string
{
    $n = count($vals);
    if ($n < 2) {
        return '';
    }
    $min  = min($vals);
    $max  = max($vals);
    $span = ($max - $min) ?: 1;
    $pts  = [];
    foreach ($vals as $i => $v) {
        $pts[] = sprintf('%.1f,%.1f', ($i / ($n - 1)) * 112, 29 - (($v - $min) / $span) * 26);
    }
    $str = implode(' ', $pts);
    return '<polygon points="0,32 ' . $str . ' 112,32" fill="currentColor" fill-opacity="0.12"/>'
         . '<polyline points="' . $str . '" fill="none" stroke="currentColor" stroke-width="2" '
         . 'stroke-linecap="round" stroke-linejoin="round"/>';
}

/* ============================================================== payload === */

/** JSON payload for the ?api=stats poll endpoint. */
function stats_payload(): array
{
    $t      = telemetry();
    $bucket = intdiv(time(), 4);
    $h      = (int) gmdate('G') + ((int) gmdate('i')) / 60;
    $curve  = diurnal($h);

    return [
        'ts'         => $t['ts'],
        'sessions'   => $t['sessions'],
        'rps'        => $t['rps'],
        'p95_ms'     => $t['p95_ms'],
        'error_rate' => $t['error_rate'],
        'users'      => $t['users'],
        'mrr'        => $t['mrr'],
        'spark'      => [
            'sessions' => spark('spk-s', 20, 3560, 4340),
            'p95'      => spark('spk-p', 20, 92, 150),
        ],
        'point'      => [
            'label'    => gmdate('H:i'),
            'revenue'  => (int) max(12, round(41 + 26 * $curve + ikey("rev-$bucket", -5, 7))),
            'sessions' => (int) max(420, round(3760 + 870 * $curve + ikey("s$bucket", -140, 140))),
        ],
        'logs'       => recent_logs(3),
        'status'     => status_codes(),
    ];
}

/* ===================================================== API  dispatch ===== */

$api = isset($_GET['api']) ? (string) $_GET['api'] : null;

if ($api !== null) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    if ($api === 'ping') {
        $ping = [
            'status'  => 'ok',
            'service' => 'nimbus-analytics',
            'php'     => PHP_VERSION,
            'sapi'    => PHP_SAPI,
            'time'    => gmdate('c'),
        ];
        // Opt-in worker PID for the cross-request (same-worker) exercise.
        // Not exposed by default: the lab starts as a realistic fingerprint surface.
        if (isset($_GET['showpid'])) {
            $ping['pid'] = getmypid();
        }
        echo json_encode($ping);
    } elseif ($api === 'stats') {
        echo json_encode(stats_payload(), JSON_UNESCAPED_SLASHES);
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'unknown endpoint', 'endpoint' => $api]);
    }
    exit;
}

/* ====================================================== page  assembly === */

$snap    = telemetry();
$series  = series24();
$sparks  = [
    'users'    => spark('spk-u', 20, 38, 96),
    'mrr'      => spark('spk-m', 20, 42, 98),
    'sessions' => spark('spk-s', 20, 3560, 4340),
    'p95'      => spark('spk-p', 20, 92, 150),
];
$weekly  = weekly_bars();
$status  = status_codes();
$logs    = recent_logs(10);

$funnel = [
    ['Sessions',         1284300, 100.0],
    ['Signups',           312046,  24.3],
    ['Activated',         164311,  12.8],
    ['Paid conversions',   52656,   4.1],
];

$topPages = [
    ['/dashboard',                  412304, '4m 12s', 22.1],
    ['/reports/quarterly-summary',  298114, '6m 48s', 18.4],
    ['/pricing',                    244920, '2m 05s', 38.9],
    ['/api/v2/metrics/query',       198411, '—',      2.1],
    ['/docs/getting-started',       121307, '5m 22s', 27.6],
    ['/login',                       98220, '1m 12s', 12.3],
];

$cohortLabels = [];
for ($i = 4; $i >= 0; $i--) {
    $cohortLabels[] = gmdate('M Y', strtotime("-{$i} months"));
}
$cohortVisible = [3, 7, 8, 8, 8]; // weeks of data per cohort (index 0 = newest)

$opcache = 'extension not loaded';
if (function_exists('opcache_get_status')) {
    $st = @opcache_get_status(false);
    $opcache = is_array($st) ? 'enabled' : 'disabled';
}

$rtPhp = [
    'PHP version'      => PHP_VERSION,
    'SAPI interface'   => PHP_SAPI,
    'Zend Engine'      => 'v' . zend_version(),
    'OPcache'          => $opcache,
    'Integer size'     => (PHP_INT_SIZE * 8) . '-bit',
    'Operating system' => php_uname('s') . ' ' . php_uname('r') . ' (' . php_uname('m') . ')',
];
$rtServer = [
    'Server software'  => isset($_SERVER['SERVER_SOFTWARE']) ? (string) $_SERVER['SERVER_SOFTWARE'] : '—',
    'Front door'       => 'nginx :80 → PHP-FPM 127.0.0.1:9000',
    'Document root'    => isset($_SERVER['DOCUMENT_ROOT']) ? (string) $_SERVER['DOCUMENT_ROOT'] : '/var/www/html',
    'Hostname'         => gethostname() ?: '—',
    'Process uptime'   => container_uptime(),
    'Local time'       => gmdate('Y-m-d H:i:s') . ' UTC',
];
$rtLimits = [
    'memory_limit'        => ini_val('memory_limit'),
    'upload_max_filesize' => ini_val('upload_max_filesize'),
    'post_max_size'       => ini_val('post_max_size'),
    'max_execution_time'  => ini_val('max_execution_time'),
    'display_errors'      => ini_val('display_errors'),
    'expose_php'          => ini_val('expose_php'),
    'disable_functions'   => ini_val('disable_functions') !== '' ? ini_val('disable_functions') : '(none)',
    'allow_url_include'   => ini_val('allow_url_include'),
    'cgi.fix_pathinfo'    => ini_val('cgi.fix_pathinfo'),
];
$exts = get_loaded_extensions();
sort($exts);

$integrations = [
    ['Snowflake',  'DW',     'connected', 'Synced 4m ago',    'from-sky-400 to-blue-600'],
    ['Salesforce', 'CRM',    'connected', 'Synced 11m ago',   'from-emerald-400 to-teal-600'],
    ['Slack',      'Alerts', 'connected', 'Webhook active',   'from-fuchsia-400 to-purple-600'],
    ['Segment',    'CDP',    'pending',   'Awaiting OAuth',   'from-amber-400 to-orange-600'],
    ['BigQuery',   'DW',     'disabled',  'Re-auth required', 'from-blue-400 to-indigo-600'],
    ['HubSpot',    'MKT',    'connected', 'Synced 32m ago',   'from-orange-400 to-rose-600'],
    ['Zendesk',    'SUP',    'connected', 'Synced 2m ago',    'from-lime-400 to-green-600'],
    ['Datadog',    'OBS',    'pending',   'Invite sent',      'from-rose-400 to-red-600'],
];

$boot = [
    'pollMs' => 4000,
    'php'    => PHP_VERSION,
    'sapi'   => PHP_SAPI,
    'series' => $series,
    'status' => $status,
];
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<meta name="description" content="Nimbus Analytics — enterprise revenue intelligence platform">
<title>Nimbus Analytics · Enterprise Dashboard</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%234f46e5'/%3E%3Cpath d='M7 22l5-7 4 4 8-10' stroke='white' stroke-width='2.6' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<script>
/* theme boot — must run before first paint to avoid a flash of the wrong theme */
(function () {
  try {
    var t = localStorage.getItem('nimbus-theme');
    var d = t ? t === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (d) document.documentElement.classList.add('dark');
  } catch (e) {}
})();
</script>
<style>
*,:after,:before{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-pan-x: ;--tw-pan-y: ;--tw-pinch-zoom: ;--tw-scroll-snap-strictness:proximity;--tw-gradient-from-position: ;--tw-gradient-via-position: ;--tw-gradient-to-position: ;--tw-ordinal: ;--tw-slashed-zero: ;--tw-numeric-figure: ;--tw-numeric-spacing: ;--tw-numeric-fraction: ;--tw-ring-inset: ;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:rgba(59,130,246,.5);--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;--tw-blur: ;--tw-brightness: ;--tw-contrast: ;--tw-grayscale: ;--tw-hue-rotate: ;--tw-invert: ;--tw-saturate: ;--tw-sepia: ;--tw-drop-shadow: ;--tw-backdrop-blur: ;--tw-backdrop-brightness: ;--tw-backdrop-contrast: ;--tw-backdrop-grayscale: ;--tw-backdrop-hue-rotate: ;--tw-backdrop-invert: ;--tw-backdrop-opacity: ;--tw-backdrop-saturate: ;--tw-backdrop-sepia: ;--tw-contain-size: ;--tw-contain-layout: ;--tw-contain-paint: ;--tw-contain-style: }::backdrop{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-pan-x: ;--tw-pan-y: ;--tw-pinch-zoom: ;--tw-scroll-snap-strictness:proximity;--tw-gradient-from-position: ;--tw-gradient-via-position: ;--tw-gradient-to-position: ;--tw-ordinal: ;--tw-slashed-zero: ;--tw-numeric-figure: ;--tw-numeric-spacing: ;--tw-numeric-fraction: ;--tw-ring-inset: ;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:rgba(59,130,246,.5);--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;--tw-blur: ;--tw-brightness: ;--tw-contrast: ;--tw-grayscale: ;--tw-hue-rotate: ;--tw-invert: ;--tw-saturate: ;--tw-sepia: ;--tw-drop-shadow: ;--tw-backdrop-blur: ;--tw-backdrop-brightness: ;--tw-backdrop-contrast: ;--tw-backdrop-grayscale: ;--tw-backdrop-hue-rotate: ;--tw-backdrop-invert: ;--tw-backdrop-opacity: ;--tw-backdrop-saturate: ;--tw-backdrop-sepia: ;--tw-contain-size: ;--tw-contain-layout: ;--tw-contain-paint: ;--tw-contain-style: }/*! tailwindcss v3.4.17 | MIT License | https://tailwindcss.com*/*,:after,:before{box-sizing:border-box;border:0 solid #e5e7eb}:after,:before{--tw-content:""}:host,html{line-height:1.5;-webkit-text-size-adjust:100%;-moz-tab-size:4;-o-tab-size:4;tab-size:4;font-family:ui-sans-serif,system-ui,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji;font-feature-settings:normal;font-variation-settings:normal;-webkit-tap-highlight-color:transparent}body{margin:0;line-height:inherit}hr{height:0;color:inherit;border-top-width:1px}abbr:where([title]){-webkit-text-decoration:underline dotted;text-decoration:underline dotted}h1,h2,h3,h4,h5,h6{font-size:inherit;font-weight:inherit}a{color:inherit;text-decoration:inherit}b,strong{font-weight:bolder}code,kbd,pre,samp{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace;font-feature-settings:normal;font-variation-settings:normal;font-size:1em}small{font-size:80%}sub,sup{font-size:75%;line-height:0;position:relative;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}table{text-indent:0;border-color:inherit;border-collapse:collapse}button,input,optgroup,select,textarea{font-family:inherit;font-feature-settings:inherit;font-variation-settings:inherit;font-size:100%;font-weight:inherit;line-height:inherit;letter-spacing:inherit;color:inherit;margin:0;padding:0}button,select{text-transform:none}button,input:where([type=button]),input:where([type=reset]),input:where([type=submit]){-webkit-appearance:button;background-color:transparent;background-image:none}:-moz-focusring{outline:auto}:-moz-ui-invalid{box-shadow:none}progress{vertical-align:baseline}::-webkit-inner-spin-button,::-webkit-outer-spin-button{height:auto}[type=search]{-webkit-appearance:textfield;outline-offset:-2px}::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{-webkit-appearance:button;font:inherit}summary{display:list-item}blockquote,dd,dl,figure,h1,h2,h3,h4,h5,h6,hr,p,pre{margin:0}fieldset{margin:0}fieldset,legend{padding:0}menu,ol,ul{list-style:none;margin:0;padding:0}dialog{padding:0}textarea{resize:vertical}input::-moz-placeholder,textarea::-moz-placeholder{opacity:1;color:#9ca3af}input::placeholder,textarea::placeholder{opacity:1;color:#9ca3af}[role=button],button{cursor:pointer}:disabled{cursor:default}audio,canvas,embed,iframe,img,object,svg,video{display:block;vertical-align:middle}img,video{max-width:100%;height:auto}[hidden]:where(:not([hidden=until-found])){display:none}.pointer-events-none{pointer-events:none}.fixed{position:fixed}.absolute{position:absolute}.relative{position:relative}.sticky{position:sticky}.inset-0{inset:0}.inset-y-0{top:0;bottom:0}.bottom-5{bottom:1.25rem}.left-0{left:0}.right-1\.5{right:.375rem}.right-5{right:1.25rem}.top-0{top:0}.top-1\.5{top:.375rem}.-z-10{z-index:-10}.z-20{z-index:20}.z-30{z-index:30}.z-40{z-index:40}.z-50{z-index:50}.mx-3{margin-left:.75rem;margin-right:.75rem}.mx-auto{margin-left:auto;margin-right:auto}.mb-1\.5{margin-bottom:.375rem}.mb-3{margin-bottom:.75rem}.ml-1{margin-left:.25rem}.ml-auto{margin-left:auto}.mt-0\.5{margin-top:.125rem}.mt-1{margin-top:.25rem}.mt-1\.5{margin-top:.375rem}.mt-2{margin-top:.5rem}.mt-3{margin-top:.75rem}.mt-4{margin-top:1rem}.mt-5{margin-top:1.25rem}.mt-6{margin-top:1.5rem}.block{display:block}.flex{display:flex}.inline-flex{display:inline-flex}.table{display:table}.grid{display:grid}.hidden{display:none}.h-1\.5{height:.375rem}.h-10{height:2.5rem}.h-11{height:2.75rem}.h-16{height:4rem}.h-2{height:.5rem}.h-2\.5{height:.625rem}.h-3{height:.75rem}.h-32{height:8rem}.h-4{height:1rem}.h-40{height:10rem}.h-5{height:1.25rem}.h-8{height:2rem}.h-9{height:2.25rem}.h-full{height:100%}.max-h-\[430px\]{max-height:430px}.min-h-screen{min-height:100vh}.w-1\.5{width:.375rem}.w-10{width:2.5rem}.w-11{width:2.75rem}.w-2{width:.5rem}.w-28{width:7rem}.w-3{width:.75rem}.w-32{width:8rem}.w-4{width:1rem}.w-5{width:1.25rem}.w-64{width:16rem}.w-72{width:18rem}.w-8{width:2rem}.w-9{width:2.25rem}.w-full{width:100%}.min-w-0{min-width:0}.min-w-\[560px\]{min-width:560px}.max-w-\[1440px\]{max-width:1440px}.flex-1{flex:1 1 0%}.shrink-0{flex-shrink:0}.border-separate{border-collapse:separate}.border-spacing-1{--tw-border-spacing-x:0.25rem;--tw-border-spacing-y:0.25rem;border-spacing:var(--tw-border-spacing-x) var(--tw-border-spacing-y)}.-translate-x-full{--tw-translate-x:-100%}.-translate-x-full,.translate-y-2{transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}.translate-y-2{--tw-translate-y:0.5rem}.-rotate-90{--tw-rotate:-90deg;transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}@keyframes ping{75%,to{transform:scale(2);opacity:0}}.animate-ping{animation:ping 1s cubic-bezier(0,0,.2,1) infinite}.resize{resize:both}.grid-cols-1{grid-template-columns:repeat(1,minmax(0,1fr))}.grid-cols-2{grid-template-columns:repeat(2,minmax(0,1fr))}.flex-col{flex-direction:column}.flex-wrap{flex-wrap:wrap}.place-items-center{place-items:center}.items-start{align-items:flex-start}.items-end{align-items:flex-end}.items-center{align-items:center}.items-baseline{align-items:baseline}.justify-end{justify-content:flex-end}.justify-between{justify-content:space-between}.gap-1\.5{gap:.375rem}.gap-2{gap:.5rem}.gap-2\.5{gap:.625rem}.gap-3{gap:.75rem}.gap-4{gap:1rem}.gap-5{gap:1.25rem}.space-y-1>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-top:calc(.25rem*(1 - var(--tw-space-y-reverse)));margin-bottom:calc(.25rem*var(--tw-space-y-reverse))}.space-y-2>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-top:calc(.5rem*(1 - var(--tw-space-y-reverse)));margin-bottom:calc(.5rem*var(--tw-space-y-reverse))}.space-y-3>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-top:calc(.75rem*(1 - var(--tw-space-y-reverse)));margin-bottom:calc(.75rem*var(--tw-space-y-reverse))}.space-y-4>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-top:calc(1rem*(1 - var(--tw-space-y-reverse)));margin-bottom:calc(1rem*var(--tw-space-y-reverse))}.space-y-5>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-top:calc(1.25rem*(1 - var(--tw-space-y-reverse)));margin-bottom:calc(1.25rem*var(--tw-space-y-reverse))}.space-y-6>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-top:calc(1.5rem*(1 - var(--tw-space-y-reverse)));margin-bottom:calc(1.5rem*var(--tw-space-y-reverse))}.divide-y>:not([hidden])~:not([hidden]){--tw-divide-y-reverse:0;border-top-width:calc(1px*(1 - var(--tw-divide-y-reverse)));border-bottom-width:calc(1px*var(--tw-divide-y-reverse))}.divide-slate-100>:not([hidden])~:not([hidden]){--tw-divide-opacity:1;border-color:rgb(241 245 249/var(--tw-divide-opacity,1))}.overflow-auto{overflow:auto}.overflow-hidden{overflow:hidden}.overflow-x-auto{overflow-x:auto}.overflow-y-auto{overflow-y:auto}.truncate{overflow:hidden;text-overflow:ellipsis}.truncate,.whitespace-nowrap{white-space:nowrap}.rounded{border-radius:.25rem}.rounded-2xl{border-radius:1rem}.rounded-full{border-radius:9999px}.rounded-lg{border-radius:.5rem}.rounded-md{border-radius:.375rem}.rounded-xl{border-radius:.75rem}.border{border-width:1px}.border-b{border-bottom-width:1px}.border-r{border-right-width:1px}.border-t{border-top-width:1px}.border-amber-300\/50{border-color:rgba(252,211,77,.5)}.border-amber-400\/40{border-color:rgba(251,191,36,.4)}.border-emerald-500\/30{border-color:rgba(16,185,129,.3)}.border-rose-300{--tw-border-opacity:1;border-color:rgb(253 164 175/var(--tw-border-opacity,1))}.border-rose-300\/60{border-color:rgba(253,164,175,.6)}.border-slate-100{--tw-border-opacity:1;border-color:rgb(241 245 249/var(--tw-border-opacity,1))}.border-slate-200{--tw-border-opacity:1;border-color:rgb(226 232 240/var(--tw-border-opacity,1))}.border-slate-200\/80{border-color:rgba(226,232,240,.8)}.bg-amber-100{--tw-bg-opacity:1;background-color:rgb(254 243 199/var(--tw-bg-opacity,1))}.bg-amber-400{--tw-bg-opacity:1;background-color:rgb(251 191 36/var(--tw-bg-opacity,1))}.bg-amber-50{--tw-bg-opacity:1;background-color:rgb(255 251 235/var(--tw-bg-opacity,1))}.bg-amber-500{--tw-bg-opacity:1;background-color:rgb(245 158 11/var(--tw-bg-opacity,1))}.bg-emerald-100{--tw-bg-opacity:1;background-color:rgb(209 250 229/var(--tw-bg-opacity,1))}.bg-emerald-400{--tw-bg-opacity:1;background-color:rgb(52 211 153/var(--tw-bg-opacity,1))}.bg-emerald-50{--tw-bg-opacity:1;background-color:rgb(236 253 245/var(--tw-bg-opacity,1))}.bg-emerald-500{--tw-bg-opacity:1;background-color:rgb(16 185 129/var(--tw-bg-opacity,1))}.bg-indigo-100{--tw-bg-opacity:1;background-color:rgb(224 231 255/var(--tw-bg-opacity,1))}.bg-indigo-50{--tw-bg-opacity:1;background-color:rgb(238 242 255/var(--tw-bg-opacity,1))}.bg-indigo-500{--tw-bg-opacity:1;background-color:rgb(99 102 241/var(--tw-bg-opacity,1))}.bg-indigo-500\/40{background-color:rgba(99,102,241,.4)}.bg-indigo-600{--tw-bg-opacity:1;background-color:rgb(79 70 229/var(--tw-bg-opacity,1))}.bg-rose-100{--tw-bg-opacity:1;background-color:rgb(255 228 230/var(--tw-bg-opacity,1))}.bg-rose-400{--tw-bg-opacity:1;background-color:rgb(251 113 133/var(--tw-bg-opacity,1))}.bg-rose-50{--tw-bg-opacity:1;background-color:rgb(255 241 242/var(--tw-bg-opacity,1))}.bg-rose-50\/50{background-color:rgba(255,241,242,.5)}.bg-rose-500{--tw-bg-opacity:1;background-color:rgb(244 63 94/var(--tw-bg-opacity,1))}.bg-rose-600{--tw-bg-opacity:1;background-color:rgb(225 29 72/var(--tw-bg-opacity,1))}.bg-sky-50{--tw-bg-opacity:1;background-color:rgb(240 249 255/var(--tw-bg-opacity,1))}.bg-slate-100{--tw-bg-opacity:1;background-color:rgb(241 245 249/var(--tw-bg-opacity,1))}.bg-slate-400{--tw-bg-opacity:1;background-color:rgb(148 163 184/var(--tw-bg-opacity,1))}.bg-slate-50{--tw-bg-opacity:1;background-color:rgb(248 250 252/var(--tw-bg-opacity,1))}.bg-slate-950\/50{background-color:rgba(2,6,23,.5)}.bg-transparent{background-color:transparent}.bg-violet-50{--tw-bg-opacity:1;background-color:rgb(245 243 255/var(--tw-bg-opacity,1))}.bg-white{--tw-bg-opacity:1;background-color:rgb(255 255 255/var(--tw-bg-opacity,1))}.bg-white\/80{background-color:hsla(0,0%,100%,.8)}.bg-\[radial-gradient\(60rem_40rem_at_115\%_-10\%\2c rgba\(79\2c 70\2c 229\2c \.12\)\2c transparent\)\2c radial-gradient\(50rem_30rem_at_-10\%_110\%\2c rgba\(14\2c 165\2c 233\2c \.10\)\2c transparent\)\]{background-image:radial-gradient(60rem 40rem at 115% -10%,rgba(79,70,229,.12),transparent),radial-gradient(50rem 30rem at -10% 110%,rgba(14,165,233,.1),transparent)}.bg-gradient-to-br{background-image:linear-gradient(to bottom right,var(--tw-gradient-stops))}.bg-gradient-to-r{background-image:linear-gradient(to right,var(--tw-gradient-stops))}.from-amber-400{--tw-gradient-from:#fbbf24 var(--tw-gradient-from-position);--tw-gradient-to:rgba(251,191,36,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.from-blue-400{--tw-gradient-from:#60a5fa var(--tw-gradient-from-position);--tw-gradient-to:rgba(96,165,250,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.from-emerald-400{--tw-gradient-from:#34d399 var(--tw-gradient-from-position);--tw-gradient-to:rgba(52,211,153,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.from-fuchsia-400{--tw-gradient-from:#e879f9 var(--tw-gradient-from-position);--tw-gradient-to:rgba(232,121,249,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.from-indigo-500{--tw-gradient-from:#6366f1 var(--tw-gradient-from-position);--tw-gradient-to:rgba(99,102,241,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.from-lime-400{--tw-gradient-from:#a3e635 var(--tw-gradient-from-position);--tw-gradient-to:rgba(163,230,53,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.from-orange-400{--tw-gradient-from:#fb923c var(--tw-gradient-from-position);--tw-gradient-to:rgba(251,146,60,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.from-rose-400{--tw-gradient-from:#fb7185 var(--tw-gradient-from-position);--tw-gradient-to:rgba(251,113,133,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.from-sky-400{--tw-gradient-from:#38bdf8 var(--tw-gradient-from-position);--tw-gradient-to:rgba(56,189,248,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.to-blue-600{--tw-gradient-to:#2563eb var(--tw-gradient-to-position)}.to-green-600{--tw-gradient-to:#16a34a var(--tw-gradient-to-position)}.to-indigo-600{--tw-gradient-to:#4f46e5 var(--tw-gradient-to-position)}.to-orange-500{--tw-gradient-to:#f97316 var(--tw-gradient-to-position)}.to-orange-600{--tw-gradient-to:#ea580c var(--tw-gradient-to-position)}.to-purple-600{--tw-gradient-to:#9333ea var(--tw-gradient-to-position)}.to-red-600{--tw-gradient-to:#dc2626 var(--tw-gradient-to-position)}.to-rose-600{--tw-gradient-to:#e11d48 var(--tw-gradient-to-position)}.to-teal-600{--tw-gradient-to:#0d9488 var(--tw-gradient-to-position)}.to-violet-500{--tw-gradient-to:#8b5cf6 var(--tw-gradient-to-position)}.to-violet-600{--tw-gradient-to:#7c3aed var(--tw-gradient-to-position)}.p-3{padding:.75rem}.p-4{padding:1rem}.p-5{padding:1.25rem}.px-1{padding-left:.25rem;padding-right:.25rem}.px-1\.5{padding-left:.375rem;padding-right:.375rem}.px-2{padding-left:.5rem;padding-right:.5rem}.px-2\.5{padding-left:.625rem;padding-right:.625rem}.px-3{padding-left:.75rem;padding-right:.75rem}.px-4{padding-left:1rem;padding-right:1rem}.px-5{padding-left:1.25rem;padding-right:1.25rem}.px-6{padding-left:1.5rem;padding-right:1.5rem}.py-0\.5{padding-top:.125rem;padding-bottom:.125rem}.py-1{padding-top:.25rem;padding-bottom:.25rem}.py-1\.5{padding-top:.375rem;padding-bottom:.375rem}.py-2{padding-top:.5rem;padding-bottom:.5rem}.py-2\.5{padding-top:.625rem;padding-bottom:.625rem}.py-3{padding-top:.75rem;padding-bottom:.75rem}.py-3\.5{padding-top:.875rem;padding-bottom:.875rem}.py-4{padding-top:1rem;padding-bottom:1rem}.py-5{padding-top:1.25rem;padding-bottom:1.25rem}.py-6{padding-top:1.5rem;padding-bottom:1.5rem}.pb-2{padding-bottom:.5rem}.pb-5{padding-bottom:1.25rem}.pt-4{padding-top:1rem}.text-left{text-align:left}.text-center{text-align:center}.font-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace}.font-sans{font-family:ui-sans-serif,system-ui,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji}.text-3xl{font-size:1.875rem;line-height:2.25rem}.text-\[10px\]{font-size:10px}.text-\[11px\]{font-size:11px}.text-\[13px\]{font-size:13px}.text-\[15px\]{font-size:15px}.text-\[9px\]{font-size:9px}.text-base{font-size:1rem;line-height:1.5rem}.text-sm{font-size:.875rem;line-height:1.25rem}.text-xl{font-size:1.25rem;line-height:1.75rem}.text-xs{font-size:.75rem;line-height:1rem}.font-bold{font-weight:700}.font-medium{font-weight:500}.font-normal{font-weight:400}.font-semibold{font-weight:600}.uppercase{text-transform:uppercase}.tabular-nums{--tw-numeric-spacing:tabular-nums;font-variant-numeric:var(--tw-ordinal) var(--tw-slashed-zero) var(--tw-numeric-figure) var(--tw-numeric-spacing) var(--tw-numeric-fraction)}.leading-relaxed{line-height:1.625}.tracking-tight{letter-spacing:-.025em}.tracking-wider{letter-spacing:.05em}.tracking-widest{letter-spacing:.1em}.text-amber-600{--tw-text-opacity:1;color:rgb(217 119 6/var(--tw-text-opacity,1))}.text-amber-700{--tw-text-opacity:1;color:rgb(180 83 9/var(--tw-text-opacity,1))}.text-amber-700\/80{color:rgba(180,83,9,.8)}.text-amber-800{--tw-text-opacity:1;color:rgb(146 64 14/var(--tw-text-opacity,1))}.text-amber-900{--tw-text-opacity:1;color:rgb(120 53 15/var(--tw-text-opacity,1))}.text-emerald-500{--tw-text-opacity:1;color:rgb(16 185 129/var(--tw-text-opacity,1))}.text-emerald-600{--tw-text-opacity:1;color:rgb(5 150 105/var(--tw-text-opacity,1))}.text-emerald-700{--tw-text-opacity:1;color:rgb(4 120 87/var(--tw-text-opacity,1))}.text-emerald-800{--tw-text-opacity:1;color:rgb(6 95 70/var(--tw-text-opacity,1))}.text-indigo-200{--tw-text-opacity:1;color:rgb(199 210 254/var(--tw-text-opacity,1))}.text-indigo-500{--tw-text-opacity:1;color:rgb(99 102 241/var(--tw-text-opacity,1))}.text-indigo-600{--tw-text-opacity:1;color:rgb(79 70 229/var(--tw-text-opacity,1))}.text-indigo-700{--tw-text-opacity:1;color:rgb(67 56 202/var(--tw-text-opacity,1))}.text-indigo-900{--tw-text-opacity:1;color:rgb(49 46 129/var(--tw-text-opacity,1))}.text-rose-600{--tw-text-opacity:1;color:rgb(225 29 72/var(--tw-text-opacity,1))}.text-rose-600\/80{color:rgba(225,29,72,.8)}.text-rose-700{--tw-text-opacity:1;color:rgb(190 18 60/var(--tw-text-opacity,1))}.text-sky-500{--tw-text-opacity:1;color:rgb(14 165 233/var(--tw-text-opacity,1))}.text-sky-600{--tw-text-opacity:1;color:rgb(2 132 199/var(--tw-text-opacity,1))}.text-slate-300{--tw-text-opacity:1;color:rgb(203 213 225/var(--tw-text-opacity,1))}.text-slate-400{--tw-text-opacity:1;color:rgb(148 163 184/var(--tw-text-opacity,1))}.text-slate-500{--tw-text-opacity:1;color:rgb(100 116 139/var(--tw-text-opacity,1))}.text-slate-600{--tw-text-opacity:1;color:rgb(71 85 105/var(--tw-text-opacity,1))}.text-slate-700{--tw-text-opacity:1;color:rgb(51 65 85/var(--tw-text-opacity,1))}.text-slate-800{--tw-text-opacity:1;color:rgb(30 41 59/var(--tw-text-opacity,1))}.text-slate-900{--tw-text-opacity:1;color:rgb(15 23 42/var(--tw-text-opacity,1))}.text-violet-500{--tw-text-opacity:1;color:rgb(139 92 246/var(--tw-text-opacity,1))}.text-violet-600{--tw-text-opacity:1;color:rgb(124 58 237/var(--tw-text-opacity,1))}.text-white{--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity,1))}.antialiased{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}.placeholder-slate-400::-moz-placeholder{--tw-placeholder-opacity:1;color:rgb(148 163 184/var(--tw-placeholder-opacity,1))}.placeholder-slate-400::placeholder{--tw-placeholder-opacity:1;color:rgb(148 163 184/var(--tw-placeholder-opacity,1))}.opacity-0{opacity:0}.opacity-75{opacity:.75}.shadow-lg{--tw-shadow:0 10px 15px -3px rgba(0,0,0,.1),0 4px 6px -4px rgba(0,0,0,.1);--tw-shadow-colored:0 10px 15px -3px var(--tw-shadow-color),0 4px 6px -4px var(--tw-shadow-color)}.shadow-lg,.shadow-sm{box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.shadow-sm{--tw-shadow:0 1px 2px 0 rgba(0,0,0,.05);--tw-shadow-colored:0 1px 2px 0 var(--tw-shadow-color)}.shadow-xl{--tw-shadow:0 20px 25px -5px rgba(0,0,0,.1),0 8px 10px -6px rgba(0,0,0,.1);--tw-shadow-colored:0 20px 25px -5px var(--tw-shadow-color),0 8px 10px -6px var(--tw-shadow-color);box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.shadow-indigo-500\/30{--tw-shadow-color:rgba(99,102,241,.3);--tw-shadow:var(--tw-shadow-colored)}.shadow-indigo-600\/30{--tw-shadow-color:rgba(79,70,229,.3);--tw-shadow:var(--tw-shadow-colored)}.shadow-rose-600\/30{--tw-shadow-color:rgba(225,29,72,.3);--tw-shadow:var(--tw-shadow-colored)}.outline-none{outline:2px solid transparent;outline-offset:2px}.invert{--tw-invert:invert(100%)}.filter,.invert{filter:var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow)}.backdrop-blur{--tw-backdrop-blur:blur(8px)}.backdrop-blur,.backdrop-blur-sm{-webkit-backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia);backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia)}.backdrop-blur-sm{--tw-backdrop-blur:blur(4px)}.transition-all{transition-property:all;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.transition-colors{transition-property:color,background-color,border-color,text-decoration-color,fill,stroke;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.transition-shadow{transition-property:box-shadow;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.transition-transform{transition-property:transform;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.duration-200{transition-duration:.2s}.duration-300{transition-duration:.3s}.duration-500{transition-duration:.5s}.hover\:border-indigo-300:hover{--tw-border-opacity:1;border-color:rgb(165 180 252/var(--tw-border-opacity,1))}.hover\:bg-indigo-500:hover{--tw-bg-opacity:1;background-color:rgb(99 102 241/var(--tw-bg-opacity,1))}.hover\:bg-rose-50:hover{--tw-bg-opacity:1;background-color:rgb(255 241 242/var(--tw-bg-opacity,1))}.hover\:bg-rose-500:hover{--tw-bg-opacity:1;background-color:rgb(244 63 94/var(--tw-bg-opacity,1))}.hover\:bg-slate-100:hover{--tw-bg-opacity:1;background-color:rgb(241 245 249/var(--tw-bg-opacity,1))}.hover\:bg-slate-50\/80:hover{background-color:rgba(248,250,252,.8)}.hover\:text-indigo-600:hover{--tw-text-opacity:1;color:rgb(79 70 229/var(--tw-text-opacity,1))}.hover\:text-slate-900:hover{--tw-text-opacity:1;color:rgb(15 23 42/var(--tw-text-opacity,1))}.hover\:shadow-md:hover{--tw-shadow:0 4px 6px -1px rgba(0,0,0,.1),0 2px 4px -2px rgba(0,0,0,.1);--tw-shadow-colored:0 4px 6px -1px var(--tw-shadow-color),0 2px 4px -2px var(--tw-shadow-color);box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.focus\:border-indigo-400:focus{--tw-border-opacity:1;border-color:rgb(129 140 248/var(--tw-border-opacity,1))}.focus\:ring-2:focus{--tw-ring-offset-shadow:var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);--tw-ring-shadow:var(--tw-ring-inset) 0 0 0 calc(2px + var(--tw-ring-offset-width)) var(--tw-ring-color);box-shadow:var(--tw-ring-offset-shadow),var(--tw-ring-shadow),var(--tw-shadow,0 0 #0000)}.focus\:ring-indigo-500\/20:focus{--tw-ring-color:rgba(99,102,241,.2)}.group:hover .group-hover\:bg-indigo-500\/70{background-color:rgba(99,102,241,.7)}.group:hover .group-hover\:text-slate-600{--tw-text-opacity:1;color:rgb(71 85 105/var(--tw-text-opacity,1))}.dark\:block:is(.dark *){display:block}.dark\:hidden:is(.dark *){display:none}.dark\:divide-slate-800:is(.dark *)>:not([hidden])~:not([hidden]){--tw-divide-opacity:1;border-color:rgb(30 41 59/var(--tw-divide-opacity,1))}.dark\:divide-slate-800\/60:is(.dark *)>:not([hidden])~:not([hidden]){border-color:rgba(30,41,59,.6)}.dark\:border-amber-500\/20:is(.dark *){border-color:rgba(245,158,11,.2)}.dark\:border-emerald-500\/25:is(.dark *){border-color:rgba(16,185,129,.25)}.dark\:border-rose-500\/25:is(.dark *){border-color:rgba(244,63,94,.25)}.dark\:border-rose-500\/30:is(.dark *){border-color:rgba(244,63,94,.3)}.dark\:border-slate-600:is(.dark *){--tw-border-opacity:1;border-color:rgb(71 85 105/var(--tw-border-opacity,1))}.dark\:border-slate-700:is(.dark *){--tw-border-opacity:1;border-color:rgb(51 65 85/var(--tw-border-opacity,1))}.dark\:border-slate-800:is(.dark *){--tw-border-opacity:1;border-color:rgb(30 41 59/var(--tw-border-opacity,1))}.dark\:border-slate-800\/60:is(.dark *){border-color:rgba(30,41,59,.6)}.dark\:border-slate-800\/80:is(.dark *){border-color:rgba(30,41,59,.8)}.dark\:bg-amber-500\/10:is(.dark *){background-color:rgba(245,158,11,.1)}.dark\:bg-amber-500\/15:is(.dark *){background-color:rgba(245,158,11,.15)}.dark\:bg-emerald-500\/10:is(.dark *){background-color:rgba(16,185,129,.1)}.dark\:bg-emerald-500\/15:is(.dark *){background-color:rgba(16,185,129,.15)}.dark\:bg-indigo-400:is(.dark *){--tw-bg-opacity:1;background-color:rgb(129 140 248/var(--tw-bg-opacity,1))}.dark\:bg-indigo-500\/10:is(.dark *){background-color:rgba(99,102,241,.1)}.dark\:bg-indigo-500\/15:is(.dark *){background-color:rgba(99,102,241,.15)}.dark\:bg-indigo-500\/25:is(.dark *){background-color:rgba(99,102,241,.25)}.dark\:bg-rose-500\/10:is(.dark *){background-color:rgba(244,63,94,.1)}.dark\:bg-rose-500\/15:is(.dark *){background-color:rgba(244,63,94,.15)}.dark\:bg-rose-500\/5:is(.dark *){background-color:rgba(244,63,94,.05)}.dark\:bg-sky-500\/10:is(.dark *){background-color:rgba(14,165,233,.1)}.dark\:bg-slate-800:is(.dark *){--tw-bg-opacity:1;background-color:rgb(30 41 59/var(--tw-bg-opacity,1))}.dark\:bg-slate-800\/40:is(.dark *){background-color:rgba(30,41,59,.4)}.dark\:bg-slate-800\/60:is(.dark *){background-color:rgba(30,41,59,.6)}.dark\:bg-slate-900:is(.dark *){--tw-bg-opacity:1;background-color:rgb(15 23 42/var(--tw-bg-opacity,1))}.dark\:bg-slate-900\/80:is(.dark *){background-color:rgba(15,23,42,.8)}.dark\:bg-slate-950:is(.dark *){--tw-bg-opacity:1;background-color:rgb(2 6 23/var(--tw-bg-opacity,1))}.dark\:bg-transparent:is(.dark *){background-color:transparent}.dark\:bg-violet-500\/10:is(.dark *){background-color:rgba(139,92,246,.1)}.dark\:text-amber-200:is(.dark *){--tw-text-opacity:1;color:rgb(253 230 138/var(--tw-text-opacity,1))}.dark\:text-amber-300:is(.dark *){--tw-text-opacity:1;color:rgb(252 211 77/var(--tw-text-opacity,1))}.dark\:text-amber-300\/70:is(.dark *){color:rgba(252,211,77,.7)}.dark\:text-amber-400:is(.dark *){--tw-text-opacity:1;color:rgb(251 191 36/var(--tw-text-opacity,1))}.dark\:text-emerald-200:is(.dark *){--tw-text-opacity:1;color:rgb(167 243 208/var(--tw-text-opacity,1))}.dark\:text-emerald-300:is(.dark *){--tw-text-opacity:1;color:rgb(110 231 183/var(--tw-text-opacity,1))}.dark\:text-emerald-400:is(.dark *){--tw-text-opacity:1;color:rgb(52 211 153/var(--tw-text-opacity,1))}.dark\:text-indigo-200:is(.dark *){--tw-text-opacity:1;color:rgb(199 210 254/var(--tw-text-opacity,1))}.dark\:text-indigo-300:is(.dark *){--tw-text-opacity:1;color:rgb(165 180 252/var(--tw-text-opacity,1))}.dark\:text-indigo-400:is(.dark *){--tw-text-opacity:1;color:rgb(129 140 248/var(--tw-text-opacity,1))}.dark\:text-rose-300:is(.dark *){--tw-text-opacity:1;color:rgb(253 164 175/var(--tw-text-opacity,1))}.dark\:text-rose-300\/60:is(.dark *){color:rgba(253,164,175,.6)}.dark\:text-rose-400:is(.dark *){--tw-text-opacity:1;color:rgb(251 113 133/var(--tw-text-opacity,1))}.dark\:text-sky-400:is(.dark *){--tw-text-opacity:1;color:rgb(56 189 248/var(--tw-text-opacity,1))}.dark\:text-slate-100:is(.dark *){--tw-text-opacity:1;color:rgb(241 245 249/var(--tw-text-opacity,1))}.dark\:text-slate-200:is(.dark *){--tw-text-opacity:1;color:rgb(226 232 240/var(--tw-text-opacity,1))}.dark\:text-slate-300:is(.dark *){--tw-text-opacity:1;color:rgb(203 213 225/var(--tw-text-opacity,1))}.dark\:text-slate-400:is(.dark *){--tw-text-opacity:1;color:rgb(148 163 184/var(--tw-text-opacity,1))}.dark\:text-slate-500:is(.dark *){--tw-text-opacity:1;color:rgb(100 116 139/var(--tw-text-opacity,1))}.dark\:text-slate-700:is(.dark *){--tw-text-opacity:1;color:rgb(51 65 85/var(--tw-text-opacity,1))}.dark\:text-violet-400:is(.dark *){--tw-text-opacity:1;color:rgb(167 139 250/var(--tw-text-opacity,1))}.dark\:text-white:is(.dark *){--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity,1))}.dark\:hover\:border-indigo-500\/40:hover:is(.dark *){border-color:rgba(99,102,241,.4)}.dark\:hover\:bg-rose-500\/10:hover:is(.dark *){background-color:rgba(244,63,94,.1)}.dark\:hover\:bg-slate-800:hover:is(.dark *){--tw-bg-opacity:1;background-color:rgb(30 41 59/var(--tw-bg-opacity,1))}.dark\:hover\:bg-slate-800\/40:hover:is(.dark *){background-color:rgba(30,41,59,.4)}.dark\:hover\:bg-slate-800\/70:hover:is(.dark *){background-color:rgba(30,41,59,.7)}.dark\:hover\:text-indigo-300:hover:is(.dark *){--tw-text-opacity:1;color:rgb(165 180 252/var(--tw-text-opacity,1))}.dark\:hover\:text-white:hover:is(.dark *){--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity,1))}.group:hover .dark\:group-hover\:text-slate-300:is(.dark *){--tw-text-opacity:1;color:rgb(203 213 225/var(--tw-text-opacity,1))}@media (min-width:640px){.sm\:block{display:block}.sm\:inline{display:inline}.sm\:grid{display:grid}.sm\:grid-cols-2{grid-template-columns:repeat(2,minmax(0,1fr))}.sm\:px-6{padding-left:1.5rem;padding-right:1.5rem}.sm\:text-lg{font-size:1.125rem;line-height:1.75rem}}@media (min-width:768px){.md\:ml-3{margin-left:.75rem}.md\:flex{display:flex}}@media (min-width:1024px){.lg\:hidden{display:none}.lg\:translate-x-0{--tw-translate-x:0px;transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}.lg\:grid-cols-2{grid-template-columns:repeat(2,minmax(0,1fr))}.lg\:pl-64{padding-left:16rem}}@media (min-width:1280px){.xl\:col-span-2{grid-column:span 2/span 2}.xl\:grid-cols-3{grid-template-columns:repeat(3,minmax(0,1fr))}.xl\:grid-cols-4{grid-template-columns:repeat(4,minmax(0,1fr))}}
</style>
<style>
/* ── Nimbus app CSS (hand-written, layered on top of the Tailwind build) ── */

/* severity badges for the operational log stream */
.lvl{display:inline-flex;align-items:center;padding:.125rem .5rem;border-radius:9999px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;
  font-weight:600;letter-spacing:.02em;line-height:1.4}
.lvl-info {background:#e0f2fe;color:#0369a1}
.lvl-warn {background:#fef3c7;color:#b45309}
.lvl-error{background:#ffe4e6;color:#be123c}
.lvl-debug{background:#f1f5f9;color:#475569}
.dark .lvl-info {background:rgba(14,165,233,.14);color:#7dd3fc}
.dark .lvl-warn {background:rgba(245,158,11,.14);color:#fcd34d}
.dark .lvl-error{background:rgba(244,63,94,.14);color:#fda4af}
.dark .lvl-debug{background:rgba(148,163,184,.14);color:#cbd5e1}

/* log filter pills */
.pill{padding:.25rem .65rem;border-radius:9999px;font-size:11px;font-weight:600;
  color:#64748b;background:transparent;border:1px solid transparent;cursor:pointer;
  transition:all .15s ease}
.pill:hover{background:rgba(100,116,139,.12)}
.pill-active{background:rgba(79,70,229,.12);color:#4f46e5;border-color:rgba(79,70,229,.3)}
.dark .pill{color:#94a3b8}
.dark .pill-active{background:rgba(99,102,241,.2);color:#a5b4fc;border-color:rgba(99,102,241,.35)}

/* sticky log table head */
.loghead th{position:sticky;top:0;z-index:1;background:#f8fafc;
  box-shadow:inset 0 -1px 0 #e2e8f0}
.dark .loghead th{background:#1e293b;box-shadow:inset 0 -1px 0 rgba(51,65,85,.8)}

/* new-row / value-tick animations */
@keyframes rowin{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.rowin{animation:rowin .4s cubic-bezier(.16,1,.3,1)}
@keyframes tickf{0%{background-color:rgba(99,102,241,.25)}100%{background-color:transparent}}
.tick{animation:tickf .9s ease-out;border-radius:6px;display:inline-block;padding:0 .25rem}

/* settings toggle switches */
.toggle{position:relative;flex:none;width:40px;height:22px;border:none;border-radius:9999px;
  background:rgba(100,116,139,.4);transition:background .2s ease;cursor:pointer}
.toggle[data-on="true"]{background:#4f46e5}
.toggle .knob{position:absolute;top:2px;left:2px;width:18px;height:18px;border-radius:9999px;
  background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.3);transition:transform .2s ease}
.toggle[data-on="true"] .knob{transform:translateX(18px)}

/* slim scrollbars */
.scroll-thin{scrollbar-width:thin;scrollbar-color:rgba(100,116,139,.4) transparent}
.scroll-thin::-webkit-scrollbar{width:8px;height:8px}
.scroll-thin::-webkit-scrollbar-thumb{background:rgba(100,116,139,.4);border-radius:8px}
.scroll-thin::-webkit-scrollbar-track{background:transparent}
</style>
</head>

<body class="min-h-screen bg-slate-100 font-sans text-slate-700 antialiased dark:bg-slate-950 dark:text-slate-300">
<div class="pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(60rem_40rem_at_115%_-10%,rgba(79,70,229,.12),transparent),radial-gradient(50rem_30rem_at_-10%_110%,rgba(14,165,233,.10),transparent)]"></div>

<!-- ══════════════════════════════  SIDEBAR  ══════════════════════════════ -->
<aside id="sidebar" class="fixed inset-y-0 left-0 z-40 flex w-64 -translate-x-full flex-col border-r border-slate-200 bg-white transition-transform duration-200 dark:border-slate-800 dark:bg-slate-900 lg:translate-x-0">
  <!-- brand -->
  <div class="flex h-16 items-center gap-2.5 border-b border-slate-200 px-5 dark:border-slate-800">
    <span class="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-indigo-500 to-violet-600 text-white shadow-lg shadow-indigo-500/30">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5"><path d="M4 19h16M6 15l4-5 3 3 5-7"/></svg>
    </span>
    <div class="min-w-0">
      <p class="truncate text-[15px] font-bold tracking-tight text-slate-900 dark:text-white">Nimbus Analytics</p>
      <p class="truncate text-[11px] font-medium text-slate-400">Revenue Intelligence</p>
    </div>
  </div>

  <!-- navigation -->
  <nav class="scroll-thin flex-1 space-y-5 overflow-y-auto px-3 py-5">
    <div>
      <p class="px-3 pb-2 text-[11px] font-semibold uppercase tracking-widest text-slate-400 dark:text-slate-500">Main</p>
      <div class="space-y-1">
        <a href="#" data-view="dashboard" class="nav-link group flex items-center gap-3 rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white shadow-sm shadow-indigo-600/30 transition-colors">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5 shrink-0 text-indigo-200"><rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/></svg>
          Dashboard
        </a>
        <a href="#" data-view="analytics" class="nav-link group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/70 dark:hover:text-white">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5 shrink-0 text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-300"><path d="M5 20v-6M10 20V8M15 20v-10M20 20V5M3.5 20h17"/></svg>
          Analytics
        </a>
      </div>
    </div>

    <div>
      <p class="px-3 pb-2 text-[11px] font-semibold uppercase tracking-widest text-slate-400 dark:text-slate-500">Operations</p>
      <div class="space-y-1">
        <a href="#" data-view="logs" class="nav-link group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/70 dark:hover:text-white">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5 shrink-0 text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-300"><rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="M7 9l3 3-3 3M13 15h4"/></svg>
          System Logs
          <span class="ml-auto rounded-full bg-indigo-100 px-2 py-0.5 text-[10px] font-bold text-indigo-700 dark:bg-indigo-500/15 dark:text-indigo-300">live</span>
        </a>
        <a href="#" data-view="integrations" class="nav-link group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/70 dark:hover:text-white">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5 shrink-0 text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-300"><path d="M9 15l6-6M11 5.5l1-1a3.5 3.5 0 015 5l-1 1M13 18.5l-1 1a3.5 3.5 0 01-5-5l1-1"/></svg>
          Integrations
          <span class="ml-auto rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-bold text-amber-700 dark:bg-amber-500/15 dark:text-amber-300">2</span>
        </a>
      </div>
    </div>

    <div>
      <p class="px-3 pb-2 text-[11px] font-semibold uppercase tracking-widest text-slate-400 dark:text-slate-500">Platform</p>
      <div class="space-y-1">
        <a href="#" data-view="runtime" class="nav-link group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/70 dark:hover:text-white">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5 shrink-0 text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-300"><rect x="7" y="7" width="10" height="10" rx="2"/><path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3"/></svg>
          Runtime Environment
        </a>
        <a href="#" data-view="settings" class="nav-link group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/70 dark:hover:text-white">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5 shrink-0 text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-300"><path d="M5 5v14M12 5v14M19 5v14"/><circle cx="5" cy="10" r="2" fill="#fff"/><circle cx="12" cy="15" r="2" fill="#fff"/><circle cx="19" cy="8" r="2" fill="#fff"/></svg>
          Settings
        </a>
      </div>
    </div>

    <div>
      <p class="px-3 pb-2 text-[11px] font-semibold uppercase tracking-widest text-rose-500 dark:text-rose-400">Security Lab</p>
      <div class="space-y-1">
        <a href="#" data-view="lab" class="nav-link group flex items-center gap-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm font-semibold text-rose-700 transition-colors hover:bg-rose-100 dark:border-rose-500/25 dark:bg-rose-500/10 dark:text-rose-300 dark:hover:bg-rose-500/15">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5 shrink-0 text-rose-500 dark:text-rose-400"><path d="M9 3h6l-1 7a5 5 0 01-4 0L9 3z"/><path d="M8 14h8"/><path d="M7 17h10"/><path d="M12 10v4"/><path d="M5 21h14"/></svg>
          Solution
          <span class="ml-auto rounded-full bg-rose-600 px-2 py-0.5 text-[10px] font-bold text-white">2 CVEs</span>
        </a>
      </div>
    </div>
  </nav>

  <!-- environment card -->
  <div class="mx-3 mb-3 rounded-xl border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-800/40">
    <div class="flex items-center justify-between">
      <span class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Environment</span>
      <span class="inline-flex items-center gap-1.5 rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-bold text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"><span class="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>PROD</span>
    </div>
    <dl class="mt-2 space-y-1 text-[11px]">
      <div class="flex justify-between gap-2"><dt class="text-slate-400">Region</dt><dd class="font-medium text-slate-600 dark:text-slate-300">us-east-1</dd></div>
      <div class="flex justify-between gap-2"><dt class="text-slate-400">Runtime</dt><dd class="font-mono font-medium text-slate-600 dark:text-slate-300">PHP <?= e(PHP_VERSION) ?></dd></div>
      <div class="flex justify-between gap-2"><dt class="text-slate-400">Uptime</dt><dd class="font-medium text-slate-600 dark:text-slate-300"><?= e(container_uptime()) ?></dd></div>
    </dl>
  </div>

  <!-- user -->
  <div class="flex items-center gap-3 border-t border-slate-200 px-4 py-3.5 dark:border-slate-800">
    <span class="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-gradient-to-br from-amber-400 to-orange-500 text-xs font-bold text-white">JD</span>
    <div class="min-w-0">
      <p class="truncate text-sm font-semibold text-slate-900 dark:text-white">Jordan Diaz</p>
      <p class="truncate text-[11px] text-slate-400">Operations Lead</p>
    </div>
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" class="ml-auto h-5 w-5 shrink-0 text-slate-400"><circle cx="12" cy="5.5" r="1" fill="currentColor"/><circle cx="12" cy="12" r="1" fill="currentColor"/><circle cx="12" cy="18.5" r="1" fill="currentColor"/></svg>
  </div>
</aside>
<div id="scrim" class="fixed inset-0 z-30 hidden bg-slate-950/50 backdrop-blur-sm lg:hidden"></div>

<div class="flex min-h-screen flex-col lg:pl-64">

  <!-- ══════════════════════════════  HEADER  ══════════════════════════════ -->
  <header class="sticky top-0 z-20 border-b border-slate-200/80 bg-white/80 backdrop-blur dark:border-slate-800/80 dark:bg-slate-900/80">
    <div class="flex h-16 items-center gap-3 px-4 sm:px-6">
      <button id="navToggle" aria-label="Toggle navigation" class="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-slate-200 text-slate-500 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:text-slate-400 dark:hover:bg-slate-800 lg:hidden">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" class="h-5 w-5"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
      </button>

      <div class="min-w-0">
        <h1 id="pageTitle" class="truncate text-base font-bold tracking-tight text-slate-900 dark:text-white sm:text-lg">Dashboard</h1>
        <p id="pageCrumb" class="hidden text-[11px] text-slate-400 sm:block">Nimbus Analytics / Overview</p>
      </div>

      <!-- search -->
      <div class="ml-auto hidden w-72 items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-800/60 md:flex">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" class="h-4 w-4 shrink-0 text-slate-400"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/></svg>
        <input type="text" placeholder="Search reports, tenants, incidents…" class="w-full bg-transparent text-slate-700 placeholder-slate-400 outline-none dark:text-slate-200">
        <kbd class="shrink-0 rounded border border-slate-200 bg-white px-1.5 py-0.5 text-[10px] font-semibold text-slate-400 dark:border-slate-600 dark:bg-slate-900">⌘K</kbd>
      </div>

      <!-- ◆ SYSTEM HEALTH STATUS badge — PHP version injected live from the runtime ◆ -->
      <div id="healthBadge" title="Runtime verified live from PHP_VERSION — confirms which engine is serving this page"
           class="ml-auto flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-50 px-3 py-1.5 dark:border-emerald-500/25 dark:bg-emerald-500/10 md:ml-3">
        <span class="relative flex h-2 w-2 shrink-0">
          <span class="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
          <span class="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
        </span>
        <span class="whitespace-nowrap text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">System Health: Operational</span>
        <span class="hidden whitespace-nowrap font-mono text-[11px] font-bold text-emerald-800 sm:inline dark:text-emerald-200">PHP&nbsp;<?= e(PHP_VERSION) ?></span>
      </div>

      <!-- notifications -->
      <button class="relative grid h-9 w-9 shrink-0 place-items-center rounded-lg text-slate-500 transition-colors hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800" aria-label="Notifications">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5"><path d="M6 9a6 6 0 1112 0c0 4 1.5 5.5 1.5 5.5h-15S6 13 6 9z"/><path d="M10.5 18.5a1.8 1.8 0 003 0"/></svg>
        <span class="absolute right-1.5 top-1.5 grid h-4 w-4 place-items-center rounded-full bg-rose-500 text-[9px] font-bold text-white">3</span>
      </button>

      <!-- theme toggle -->
      <button id="themeToggle" aria-label="Toggle dark mode" class="grid h-9 w-9 shrink-0 place-items-center rounded-lg text-slate-500 transition-colors hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" class="h-5 w-5 dark:hidden"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19"/></svg>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="hidden h-5 w-5 dark:block"><path d="M20 14.5A8.5 8.5 0 019.5 4a8.5 8.5 0 1010.5 10.5z"/></svg>
      </button>

      <span class="hidden h-8 w-8 shrink-0 place-items-center rounded-full bg-gradient-to-br from-indigo-500 to-violet-600 text-[11px] font-bold text-white sm:grid">JD</span>
    </div>
  </header>

  <!-- ══════════════════════════════  MAIN  ══════════════════════════════ -->
  <main class="mx-auto w-full max-w-[1440px] flex-1 px-4 py-6 sm:px-6">

    <!-- ══════════════════════════ DASHBOARD VIEW ══════════════════════════ -->
    <section data-view-panel="dashboard" class="space-y-6">

      <!-- metric cards -->
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">

        <!-- Users -->
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <p class="text-[13px] font-medium text-slate-500 dark:text-slate-400">Total Users</p>
              <p class="mt-1 text-3xl font-bold tracking-tight text-slate-900 tabular-nums dark:text-white"><?= number_format($snap['users']) ?></p>
            </div>
            <span class="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-sky-50 text-sky-600 dark:bg-sky-500/10 dark:text-sky-400">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" class="h-5 w-5"><circle cx="9" cy="8" r="3.2"/><path d="M3.5 19c.8-3 3-4.5 5.5-4.5s4.7 1.5 5.5 4.5"/><circle cx="17" cy="9" r="2.6"/><path d="M15.5 14.6c2 .3 3.6 1.6 4.3 4.4"/></svg>
            </span>
          </div>
          <div class="mt-3 flex items-end justify-between gap-3">
            <p class="text-xs text-slate-400"><?= delta_html($snap['users_delta']) ?> vs last month</p>
            <svg viewBox="0 0 112 32" preserveAspectRatio="none" class="h-8 w-28 shrink-0 text-sky-500"><?= svg_spark($sparks['users']) ?></svg>
          </div>
        </div>

        <!-- Revenue -->
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <p class="text-[13px] font-medium text-slate-500 dark:text-slate-400">Monthly Recurring Revenue</p>
              <p class="mt-1 text-3xl font-bold tracking-tight text-slate-900 tabular-nums dark:text-white"><?= e(compact_usd($snap['mrr'])) ?></p>
            </div>
            <span class="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-emerald-50 text-emerald-600 dark:bg-emerald-500/10 dark:text-emerald-400">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" class="h-5 w-5"><path d="M12 3v18M8 7.5c0-1.7 1.8-2.7 4-2.7s4 1 4 2.7-1.8 2.6-4 3.2-4 1.4-4 3.3 1.8 2.8 4 2.8 4-1.1 4-2.8"/></svg>
            </span>
          </div>
          <div class="mt-3 flex items-end justify-between gap-3">
            <p class="text-xs text-slate-400"><?= delta_html($snap['mrr_delta']) ?> vs last month</p>
            <svg viewBox="0 0 112 32" preserveAspectRatio="none" class="h-8 w-28 shrink-0 text-emerald-500"><?= svg_spark($sparks['mrr']) ?></svg>
          </div>
        </div>

        <!-- Active sessions (live) -->
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <p class="text-[13px] font-medium text-slate-500 dark:text-slate-400">Active Sessions</p>
              <p class="mt-1 flex items-center gap-2 text-3xl font-bold tracking-tight text-slate-900 tabular-nums dark:text-white">
                <span id="m-sessions"><?= number_format($snap['sessions']) ?></span>
                <span class="inline-flex items-center rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-bold text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300">LIVE</span>
              </p>
            </div>
            <span class="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-indigo-50 text-indigo-600 dark:bg-indigo-500/10 dark:text-indigo-400">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5"><path d="M13 2 4.5 13.5H11L9.5 22 18 10.5h-6.5L13 2z"/></svg>
            </span>
          </div>
          <div class="mt-3 flex items-end justify-between gap-3">
            <p class="text-xs text-slate-400"><?= delta_html($snap['sessions_delta']) ?> vs last hour</p>
            <svg id="spk-sessions" viewBox="0 0 112 32" preserveAspectRatio="none" class="h-8 w-28 shrink-0 text-indigo-500"><?= svg_spark($sparks['sessions']) ?></svg>
          </div>
        </div>

        <!-- p95 latency -->
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <p class="text-[13px] font-medium text-slate-500 dark:text-slate-400">Response Time <span class="text-slate-400">(p95)</span></p>
              <p class="mt-1 text-3xl font-bold tracking-tight text-slate-900 tabular-nums dark:text-white"><span id="m-p95"><?= $snap['p95_ms'] ?></span><span class="ml-1 text-base font-semibold text-slate-400">ms</span></p>
            </div>
            <span class="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-violet-50 text-violet-600 dark:bg-violet-500/10 dark:text-violet-400">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" class="h-5 w-5"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/></svg>
            </span>
          </div>
          <div class="mt-3 flex items-end justify-between gap-3">
            <p class="text-xs text-slate-400"><?= delta_html($snap['p95_delta'], true) ?> vs last hour</p>
            <svg id="spk-p95" viewBox="0 0 112 32" preserveAspectRatio="none" class="h-8 w-28 shrink-0 text-violet-500"><?= svg_spark($sparks['p95']) ?></svg>
          </div>
        </div>
      </div>

      <!-- main chart + side column -->
      <div class="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <!-- revenue & sessions chart -->
        <div class="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900 xl:col-span-2">
          <div class="flex flex-wrap items-center gap-3 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
            <div>
              <h3 class="text-sm font-bold text-slate-900 dark:text-white">Revenue &amp; Active Users</h3>
              <p class="text-[11px] text-slate-400">Hourly, last 24 hours · UTC</p>
            </div>
            <div class="ml-auto flex items-center gap-2">
              <span class="rounded-full border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-slate-500 dark:border-slate-700 dark:text-slate-400">Last 24h</span>
              <button data-toast="Export queued — you will receive an email when the CSV is ready" class="rounded-full border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-slate-500 transition-colors hover:border-indigo-300 hover:text-indigo-600 dark:border-slate-700 dark:text-slate-400 dark:hover:border-indigo-500/40 dark:hover:text-indigo-300">Export CSV</button>
            </div>
          </div>
          <div class="px-5 pb-5 pt-4">
            <div class="mb-3 flex flex-wrap items-center gap-4">
              <span class="flex items-center gap-1.5 text-xs font-medium text-slate-500 dark:text-slate-400"><span class="h-2 w-2 rounded-full bg-indigo-500"></span>Revenue ($k / hr)</span>
              <span class="flex items-center gap-1.5 text-xs font-medium text-slate-500 dark:text-slate-400"><span class="h-2 w-2 rounded-full bg-emerald-500"></span>Active sessions</span>
              <span class="ml-auto inline-flex items-center gap-1.5 rounded-full bg-rose-100 px-2 py-0.5 text-[10px] font-bold text-rose-600 dark:bg-rose-500/15 dark:text-rose-300">
                <span class="relative flex h-1.5 w-1.5"><span class="absolute h-full w-full animate-ping rounded-full bg-rose-400"></span><span class="relative h-1.5 w-1.5 rounded-full bg-rose-500"></span></span>STREAMING
              </span>
            </div>
            <div class="relative"><canvas id="chartRevenue"></canvas></div>
          </div>
        </div>

        <!-- side column: status donut + incidents -->
        <div class="flex flex-col gap-4">
          <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">Response Status Mix</h3>
            <p class="text-[11px] text-slate-400">Rolling window · all edge PoPs</p>
            <div class="mt-4 flex items-center gap-5">
              <div class="relative shrink-0">
                <?php
                $segs = [
                    ['2xx', $status['s2xx'], '#10b981'],
                    ['3xx', $status['s3xx'], '#38bdf8'],
                    ['4xx', $status['s4xx'], '#f59e0b'],
                    ['5xx', $status['s5xx'], '#f43f5e'],
                ];
                $circ = 2 * M_PI * 48;
                $off = 0.0;
                ?>
                <svg viewBox="0 0 120 120" class="h-32 w-32 -rotate-90">
                  <?php foreach ($segs as $sg): $len = $circ * $sg[1] / 100; ?>
                  <circle cx="60" cy="60" r="48" fill="none" stroke="<?= $sg[2] ?>" stroke-width="12"
                          stroke-dasharray="<?= number_format($len, 2, '.', '') ?> <?= number_format($circ - $len, 2, '.', '') ?>"
                          stroke-dashoffset="<?= number_format(-$off, 2, '.', '') ?>"></circle>
                  <?php $off += $len; endforeach; ?>
                </svg>
                <div class="absolute inset-0 grid place-items-center">
                  <div class="text-center">
                    <p class="text-xl font-bold text-slate-900 tabular-nums dark:text-white"><?= number_format($status['s2xx'] + $status['s3xx'], 1) ?>%</p>
                    <p class="text-[10px] font-medium text-slate-400">success</p>
                  </div>
                </div>
              </div>
              <ul class="min-w-0 flex-1 space-y-2 text-xs">
                <?php foreach ($segs as $sg): ?>
                <li class="flex items-center gap-2">
                  <span class="h-2 w-2 shrink-0 rounded-full" style="background: <?= $sg[2] ?>"></span>
                  <span class="font-mono text-slate-500 dark:text-slate-400"><?= $sg[0] ?></span>
                  <span class="ml-auto font-semibold text-slate-800 tabular-nums dark:text-slate-200"><?= number_format($sg[1], 2) ?>%</span>
                </li>
                <?php endforeach; ?>
              </ul>
            </div>
          </div>

          <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div class="flex items-center justify-between">
              <h3 class="text-sm font-bold text-slate-900 dark:text-white">Active Incidents</h3>
              <span class="rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-bold text-amber-700 dark:bg-amber-500/15 dark:text-amber-300">1 open</span>
            </div>
            <ul class="mt-3 space-y-3 text-xs">
              <li class="flex gap-2.5 rounded-xl border border-amber-300/50 bg-amber-50 p-3 dark:border-amber-500/20 dark:bg-amber-500/10">
                <span class="mt-0.5 h-2 w-2 shrink-0 rounded-full bg-amber-500"></span>
                <div class="min-w-0">
                  <p class="font-semibold text-amber-800 dark:text-amber-200">Degraded webhook throughput — eu-west-1</p>
                  <p class="mt-0.5 text-amber-700/80 dark:text-amber-300/70">Investigating · retry queue draining · no customer impact</p>
                </div>
              </li>
              <li class="flex gap-2.5 rounded-xl border border-slate-200 p-3 dark:border-slate-800">
                <span class="mt-0.5 h-2 w-2 shrink-0 rounded-full bg-emerald-500"></span>
                <div class="min-w-0">
                  <p class="font-semibold text-slate-700 dark:text-slate-200">Elevated p95 in ap-southeast-2 — resolved</p>
                  <p class="mt-0.5 text-slate-400">Root cause: upstream DNS failover · closed 14:02 UTC</p>
                </div>
              </li>
            </ul>
          </div>
        </div>
      </div>

      <!-- weekly bars + operational logs -->
      <div class="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <!-- weekly traffic -->
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-bold text-slate-900 dark:text-white">Traffic by Day</h3>
          <p class="text-[11px] text-slate-400">Requests per weekday (thousands)</p>
          <div class="mt-6 flex h-40 items-end gap-2.5">
            <?php foreach ($weekly['days'] as $i => $d): $v = $weekly['values'][$i]; $isToday = $i === $weekly['today']; ?>
            <div class="group flex h-full flex-1 flex-col items-center justify-end gap-2" title="<?= e($d) ?> · <?= $v ?>k requests">
              <div class="w-full rounded-md transition-all duration-500 <?= $isToday ? 'bg-indigo-600 dark:bg-indigo-400' : 'bg-indigo-500/40 group-hover:bg-indigo-500/70 dark:bg-indigo-500/25' ?>" style="height: <?= (int) round($v / 468 * 100) ?>%"></div>
              <span class="text-[10px] font-medium <?= $isToday ? 'text-indigo-600 dark:text-indigo-300' : 'text-slate-400' ?>"><?= e($d) ?></span>
            </div>
            <?php endforeach; ?>
          </div>
          <div class="mt-5 border-t border-slate-100 pt-4 dark:border-slate-800">
            <div class="flex items-center justify-between text-xs">
              <span class="text-slate-400">Peak day</span>
              <span class="font-semibold text-slate-700 dark:text-slate-200"><?= e($weekly['days'][array_search(max($weekly['values']), $weekly['values'])]) ?> · <?= max($weekly['values']) ?>k</span>
            </div>
            <div class="mt-2 flex items-center justify-between text-xs">
              <span class="text-slate-400">Requests / sec <span class="font-mono">(now)</span></span>
              <span class="font-semibold text-slate-700 tabular-nums dark:text-slate-200"><span id="m-rps"><?= number_format($snap['rps']) ?></span> rps</span>
            </div>
            <div class="mt-2 flex items-center justify-between text-xs">
              <span class="text-slate-400">Error rate</span>
              <span class="font-semibold text-slate-700 tabular-nums dark:text-slate-200"><span id="m-err"><?= number_format($snap['error_rate'], 2) ?></span>%</span>
            </div>
          </div>
        </div>

        <!-- operational system logs -->
        <div id="logsCard" style="scroll-margin-top: 5.5rem" class="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900 xl:col-span-2">
          <div class="flex flex-wrap items-center gap-3 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
            <div>
              <h3 class="text-sm font-bold text-slate-900 dark:text-white">Operational System Logs</h3>
              <p class="text-[11px] text-slate-400">Streamed from the platform event bus</p>
            </div>
            <div class="ml-auto flex items-center gap-1.5" id="logFilters">
              <button type="button" data-filter="all" class="pill pill-active">All</button>
              <button type="button" data-filter="info" class="pill">Info</button>
              <button type="button" data-filter="warn" class="pill">Warn</button>
              <button type="button" data-filter="error" class="pill">Error</button>
            </div>
          </div>
          <div class="scroll-thin max-h-[430px] overflow-auto">
            <table class="w-full text-left">
              <thead class="loghead text-[11px] uppercase tracking-wider text-slate-400">
                <tr>
                  <th class="px-3 py-2.5 font-semibold">Time (UTC)</th>
                  <th class="px-3 py-2.5 font-semibold">Severity</th>
                  <th class="px-3 py-2.5 font-semibold">Service</th>
                  <th class="px-3 py-2.5 font-semibold">Message</th>
                  <th class="px-3 py-2.5 font-semibold">Trace ID</th>
                </tr>
              </thead>
              <tbody id="logBody">
                <?php foreach ($logs as $l) {
                    render_log_row($l);
                } ?>
              </tbody>
            </table>
          </div>
          <div class="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200 px-5 py-3 text-[11px] text-slate-400 dark:border-slate-800">
            <span id="logCount"><?= count($logs) ?> events buffered</span>
            <span class="flex items-center gap-1.5">
              <span class="relative flex h-1.5 w-1.5"><span class="absolute h-full w-full animate-ping rounded-full bg-emerald-400"></span><span class="relative h-1.5 w-1.5 rounded-full bg-emerald-500"></span></span>
              streaming · last sync <span id="syncTime" class="font-mono">—</span>
            </span>
          </div>
        </div>
      </div>
    </section>

    <!-- ══════════════════════════ ANALYTICS VIEW ══════════════════════════ -->
    <section data-view-panel="analytics" class="hidden space-y-6">
      <div class="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div class="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900 xl:col-span-2">
          <div class="flex flex-wrap items-center gap-3 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
            <div>
              <h3 class="text-sm font-bold text-slate-900 dark:text-white">Active Sessions — 24h</h3>
              <p class="text-[11px] text-slate-400">Concurrent sessions across all tenants</p>
            </div>
            <span class="ml-auto inline-flex items-center gap-1.5 rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-bold text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300">
              <span class="relative flex h-1.5 w-1.5"><span class="absolute h-full w-full animate-ping rounded-full bg-emerald-400"></span><span class="relative h-1.5 w-1.5 rounded-full bg-emerald-500"></span></span>LIVE
            </span>
          </div>
          <div class="px-5 pb-5 pt-4">
            <div class="relative"><canvas id="chartSessions"></canvas></div>
          </div>
        </div>

        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-bold text-slate-900 dark:text-white">Conversion Funnel</h3>
          <p class="text-[11px] text-slate-400">Last 30 days · all channels</p>
          <div class="mt-5 space-y-5">
            <?php foreach ($funnel as $f): ?>
            <div>
              <div class="mb-1.5 flex items-baseline justify-between text-xs">
                <span class="font-medium text-slate-600 dark:text-slate-300"><?= e($f[0]) ?></span>
                <span class="font-semibold text-slate-800 tabular-nums dark:text-slate-100"><?= number_format($f[1]) ?> <span class="font-normal text-slate-400">(<?= number_format($f[2], 1) ?>%)</span></span>
              </div>
              <div class="h-2.5 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                <div class="h-full rounded-full bg-gradient-to-r from-indigo-500 to-violet-500" style="width: <?= e((string) $f[2]) ?>%"></div>
              </div>
            </div>
            <?php endforeach; ?>
          </div>
          <div class="mt-6 rounded-xl bg-indigo-50 p-3 text-[11px] leading-relaxed text-indigo-900 dark:bg-indigo-500/10 dark:text-indigo-200">
            <span class="font-bold">Insight:</span> activation improved 6.2% after the new onboarding checklist shipped in build 2026.10.
          </div>
        </div>
      </div>

      <!-- cohort retention -->
      <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">Retention by Weekly Cohort</h3>
            <p class="text-[11px] text-slate-400">Percentage of signups still active in weeks 1–8</p>
          </div>
          <span class="rounded-full border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-slate-500 dark:border-slate-700 dark:text-slate-400">W1–W8</span>
        </div>
        <div class="scroll-thin mt-4 overflow-x-auto">
          <table class="w-full min-w-[560px] border-separate border-spacing-1 text-xs">
            <thead>
              <tr class="text-[11px] text-slate-400">
                <th class="px-2 py-1 text-left font-semibold">Cohort</th>
                <?php for ($w = 1; $w <= 8; $w++): ?><th class="px-2 py-1 text-center font-semibold">W<?= $w ?></th><?php endfor; ?>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($cohortLabels as $ci => $cl): ?>
              <tr>
                <td class="whitespace-nowrap px-2 py-1 font-medium text-slate-600 dark:text-slate-300"><?= e($cl) ?></td>
                <?php for ($w = 1; $w <= 8; $w++): ?>
                  <?php if ($w > $cohortVisible[$ci]): ?>
                    <td class="rounded-md bg-slate-50 text-center text-slate-300 dark:bg-slate-800/40 dark:text-slate-700">·</td>
                  <?php else: $v = (int) round(100 * pow(0.72, $w) * (0.92 + fkey("ch-$ci-$w") * 0.16)); $a = round($v / 115, 2); ?>
                    <td class="rounded-md px-2 py-1.5 text-center font-semibold tabular-nums <?= $v > 55 ? 'text-white' : 'text-slate-600 dark:text-slate-300' ?>" style="background: rgba(79,70,229,<?= $a ?>)"><?= $v ?>%</td>
                  <?php endif; ?>
                <?php endfor; ?>
              </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>

      <!-- top pages -->
      <div class="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <div class="flex flex-wrap items-center gap-3 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
          <div>
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">Top Pages</h3>
            <p class="text-[11px] text-slate-400">Most visited routes this week</p>
          </div>
          <button data-toast="Report scheduled for delivery every Monday 08:00 UTC" class="ml-auto rounded-full border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-slate-500 transition-colors hover:border-indigo-300 hover:text-indigo-600 dark:border-slate-700 dark:text-slate-400 dark:hover:border-indigo-500/40 dark:hover:text-indigo-300">Schedule report</button>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="text-[11px] uppercase tracking-wider text-slate-400">
              <tr>
                <th class="px-5 py-3 font-semibold">Route</th>
                <th class="px-5 py-3 font-semibold">Views</th>
                <th class="px-5 py-3 font-semibold">Avg. session</th>
                <th class="px-5 py-3 font-semibold">Bounce rate</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100 dark:divide-slate-800/60">
              <?php foreach ($topPages as $p): ?>
              <tr class="transition-colors hover:bg-slate-50/80 dark:hover:bg-slate-800/40">
                <td class="whitespace-nowrap px-5 py-3 font-mono font-medium text-indigo-600 dark:text-indigo-400"><?= e($p[0]) ?></td>
                <td class="whitespace-nowrap px-5 py-3 font-semibold text-slate-800 tabular-nums dark:text-slate-200"><?= number_format($p[1]) ?></td>
                <td class="whitespace-nowrap px-5 py-3 text-slate-500 tabular-nums dark:text-slate-400"><?= e($p[2]) ?></td>
                <td class="whitespace-nowrap px-5 py-3 text-slate-500 tabular-nums dark:text-slate-400"><?= number_format($p[3], 1) ?>%</td>
              </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- ════════════════════════ INTEGRATIONS VIEW ════════════════════════ -->
    <section data-view-panel="integrations" class="hidden space-y-6">
      <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <h3 class="text-sm font-bold text-slate-900 dark:text-white">Connected Integrations</h3>
        <p class="text-[11px] text-slate-400">Data sources and destinations synced by the platform</p>
      </div>
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <?php foreach ($integrations as $it):
            [$dot, $txt, $label] = $it[2] === 'connected'
                ? ['bg-emerald-500', 'text-emerald-600 dark:text-emerald-400', 'Connected']
                : ($it[2] === 'pending'
                    ? ['bg-amber-400', 'text-amber-600 dark:text-amber-400', 'Pending']
                    : ['bg-slate-400', 'text-slate-500 dark:text-slate-400', 'Disabled']); ?>
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm transition-shadow hover:shadow-md dark:border-slate-800 dark:bg-slate-900">
          <div class="flex items-start justify-between gap-3">
            <span class="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-gradient-to-br text-sm font-bold text-white <?= e($it[4]) ?>"><?= e(substr($it[0], 0, 1)) ?></span>
            <span class="flex items-center gap-1.5 text-[11px] font-semibold <?= $txt ?>"><span class="h-1.5 w-1.5 rounded-full <?= $dot ?>"></span><?= $label ?></span>
          </div>
          <p class="mt-4 text-sm font-bold text-slate-900 dark:text-white"><?= e($it[0]) ?></p>
          <p class="text-[11px] text-slate-400"><?= e($it[1]) ?> · <?= e($it[3]) ?></p>
          <button data-toast="Configuration wizard for <?= e($it[0]) ?> is not part of this demo" class="mt-4 w-full rounded-lg border border-slate-200 py-1.5 text-xs font-semibold text-slate-600 transition-colors hover:border-indigo-300 hover:text-indigo-600 dark:border-slate-700 dark:text-slate-300 dark:hover:border-indigo-500/40 dark:hover:text-indigo-300">Configure</button>
        </div>
        <?php endforeach; ?>
      </div>
    </section>

    <!-- ══════════════════════ RUNTIME ENVIRONMENT VIEW ═════════════════════ -->
    <section data-view-panel="runtime" class="hidden space-y-6">
      <div class="rounded-2xl border border-amber-400/40 bg-amber-50 p-4 text-xs leading-relaxed text-amber-900 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-200">
        <span class="font-bold">Runtime snapshot.</span> Values below are read live from the PHP engine serving this page — use them to confirm exactly which build the lab is running before each test.
      </div>
      <div class="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">

        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div class="flex items-center gap-2.5">
            <span class="grid h-9 w-9 place-items-center rounded-lg bg-indigo-50 text-indigo-600 dark:bg-indigo-500/10 dark:text-indigo-400">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" class="h-5 w-5"><path d="M7 8h10M7 12h6"/><rect x="3" y="4" width="18" height="16" rx="2.5"/></svg>
            </span>
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">PHP Runtime</h3>
            <span class="ml-auto rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-bold text-amber-700 dark:bg-amber-500/15 dark:text-amber-300">pre-patch</span>
          </div>
          <dl class="mt-4 divide-y divide-slate-100 dark:divide-slate-800">
            <?php foreach ($rtPhp as $k => $v): ?>
            <div class="flex items-center justify-between gap-4 py-2">
              <dt class="shrink-0 text-xs font-medium text-slate-500 dark:text-slate-400"><?= e($k) ?></dt>
              <dd class="truncate font-mono text-xs font-semibold text-slate-800 dark:text-slate-200"><?= e($v) ?></dd>
            </div>
            <?php endforeach; ?>
          </dl>
        </div>

        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div class="flex items-center gap-2.5">
            <span class="grid h-9 w-9 place-items-center rounded-lg bg-sky-50 text-sky-600 dark:bg-sky-500/10 dark:text-sky-400">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" class="h-5 w-5"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.6 2.4 4 5.3 4 8.5s-1.4 6.1-4 8.5c-2.6-2.4-4-5.3-4-8.5s1.4-6.1 4-8.5z"/></svg>
            </span>
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">Web Server</h3>
          </div>
          <dl class="mt-4 divide-y divide-slate-100 dark:divide-slate-800">
            <?php foreach ($rtServer as $k => $v): ?>
            <div class="flex items-center justify-between gap-4 py-2">
              <dt class="shrink-0 text-xs font-medium text-slate-500 dark:text-slate-400"><?= e($k) ?></dt>
              <dd class="truncate font-mono text-xs font-semibold text-slate-800 dark:text-slate-200"><?= e($v) ?></dd>
            </div>
            <?php endforeach; ?>
          </dl>
        </div>

        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div class="flex items-center gap-2.5">
            <span class="grid h-9 w-9 place-items-center rounded-lg bg-rose-50 text-rose-600 dark:bg-rose-500/10 dark:text-rose-400">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5"><path d="M12 3l8 3v6c0 4.5-3.2 7.7-8 9-4.8-1.3-8-4.5-8-9V6l8-3z"/></svg>
            </span>
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">Limits &amp; Security Posture</h3>
          </div>
          <dl class="mt-4 divide-y divide-slate-100 dark:divide-slate-800">
            <?php foreach ($rtLimits as $k => $v): ?>
            <div class="flex items-center justify-between gap-4 py-2">
              <dt class="shrink-0 font-mono text-xs font-medium text-slate-500 dark:text-slate-400"><?= e($k) ?></dt>
              <dd class="truncate font-mono text-xs font-semibold text-slate-800 dark:text-slate-200"><?= e($v) ?></dd>
            </div>
            <?php endforeach; ?>
          </dl>
        </div>

        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900 xl:col-span-2">
          <div class="flex items-center gap-2.5">
            <span class="grid h-9 w-9 place-items-center rounded-lg bg-emerald-50 text-emerald-600 dark:bg-emerald-500/10 dark:text-emerald-400">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" class="h-5 w-5"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M17.5 14v7M14 17.5h7"/></svg>
            </span>
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">Loaded Extensions</h3>
            <span class="ml-auto text-[11px] font-medium text-slate-400"><?= count($exts) ?> modules</span>
          </div>
          <div class="mt-4 flex flex-wrap gap-1.5">
            <?php foreach (array_slice($exts, 0, 32) as $x): ?>
            <span class="rounded-md bg-slate-100 px-2 py-1 font-mono text-[11px] font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300"><?= e($x) ?></span>
            <?php endforeach; ?>
            <?php if (count($exts) > 32): ?>
            <span class="rounded-md bg-slate-100 px-2 py-1 font-mono text-[11px] font-medium text-slate-400 dark:bg-slate-800">+<?= count($exts) - 32 ?> more</span>
            <?php endif; ?>
          </div>
        </div>

        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div class="flex items-center gap-2.5">
            <span class="grid h-9 w-9 place-items-center rounded-lg bg-violet-50 text-violet-600 dark:bg-violet-500/10 dark:text-violet-400">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" class="h-5 w-5"><path d="M4 6h16M4 12h16M4 18h10"/><circle cx="19" cy="18" r="2"/></svg>
            </span>
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">Supervisor Processes</h3>
          </div>
          <table class="mt-4 w-full text-left text-xs">
            <thead class="text-[11px] uppercase tracking-wider text-slate-400">
              <tr><th class="py-2 font-semibold">Service</th><th class="py-2 font-semibold">State</th><th class="py-2 font-semibold">Since</th></tr>
            </thead>
            <tbody class="divide-y divide-slate-100 dark:divide-slate-800/60">
              <tr><td class="py-2 font-mono font-medium text-slate-700 dark:text-slate-200">supervisord</td><td class="py-2"><span class="lvl lvl-info">RUNNING</span></td><td class="py-2 font-mono text-slate-400">boot</td></tr>
              <tr><td class="py-2 font-mono font-medium text-slate-700 dark:text-slate-200">php-fpm</td><td class="py-2"><span class="lvl lvl-info">RUNNING</span></td><td class="py-2 font-mono text-slate-400">boot</td></tr>
              <tr><td class="py-2 font-mono font-medium text-slate-700 dark:text-slate-200">nginx</td><td class="py-2"><span class="lvl lvl-info">RUNNING</span></td><td class="py-2 font-mono text-slate-400">boot</td></tr>
            </tbody>
          </table>
          <p class="mt-4 text-[11px] leading-relaxed text-slate-400">Managed by supervisord (PID 1). Verify with <code class="rounded bg-slate-100 px-1 py-0.5 font-mono dark:bg-slate-800">docker exec php2shell-vm supervisorctl status</code>.</p>
        </div>
      </div>
    </section>

    <!-- ══════════════════════════ SETTINGS VIEW ══════════════════════════ -->
    <section data-view-panel="settings" class="hidden space-y-6">
      <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-bold text-slate-900 dark:text-white">Organization</h3>
          <p class="text-[11px] text-slate-400">Workspace identity and defaults</p>
          <div class="mt-4 space-y-4">
            <div>
              <label class="mb-1.5 block text-xs font-semibold text-slate-600 dark:text-slate-300">Company name</label>
              <input type="text" value="Acme Corporation" class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-800 shadow-sm outline-none transition-colors focus:border-indigo-400 focus:ring-2 focus:ring-indigo-500/20 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-100">
            </div>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="mb-1.5 block text-xs font-semibold text-slate-600 dark:text-slate-300">Workspace slug</label>
                <input type="text" value="acme-prod" class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-sm text-slate-800 shadow-sm outline-none transition-colors focus:border-indigo-400 focus:ring-2 focus:ring-indigo-500/20 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-100">
              </div>
              <div>
                <label class="mb-1.5 block text-xs font-semibold text-slate-600 dark:text-slate-300">Data region</label>
                <select class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-800 shadow-sm outline-none transition-colors focus:border-indigo-400 focus:ring-2 focus:ring-indigo-500/20 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-100"><option>us-east-1</option><option>eu-west-1</option><option>ap-southeast-2</option></select>
              </div>
            </div>
            <button data-toast="Organization settings saved (simulated)" class="rounded-lg bg-indigo-600 px-4 py-2 text-xs font-bold text-white shadow-sm shadow-indigo-600/30 transition-colors hover:bg-indigo-500">Save changes</button>
          </div>
        </div>

        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-bold text-slate-900 dark:text-white">Authentication &amp; Security</h3>
          <p class="text-[11px] text-slate-400">Access policy for workspace members</p>
          <ul class="mt-4 divide-y divide-slate-100 dark:divide-slate-800">
            <li class="flex items-center justify-between gap-4 py-3">
              <div><p class="text-xs font-semibold text-slate-700 dark:text-slate-200">Require SSO for all members</p><p class="text-[11px] text-slate-400">SAML 2.0 · Okta preview tenant</p></div>
              <button type="button" class="toggle" data-on="true" role="switch" aria-checked="true"><span class="knob"></span></button>
            </li>
            <li class="flex items-center justify-between gap-4 py-3">
              <div><p class="text-xs font-semibold text-slate-700 dark:text-slate-200">Enforce IP allowlist for API</p><p class="text-[11px] text-slate-400">3 CIDR ranges configured</p></div>
              <button type="button" class="toggle" data-on="false" role="switch" aria-checked="false"><span class="knob"></span></button>
            </li>
            <li class="flex items-center justify-between gap-4 py-3">
              <div><p class="text-xs font-semibold text-slate-700 dark:text-slate-200">Strict TLS (1.3 only)</p><p class="text-[11px] text-slate-400">Terminate at the edge load balancer</p></div>
              <button type="button" class="toggle" data-on="true" role="switch" aria-checked="true"><span class="knob"></span></button>
            </li>
            <li class="flex items-center justify-between gap-4 py-3">
              <div><p class="text-xs font-semibold text-slate-700 dark:text-slate-200">Incident webhooks → Slack</p><p class="text-[11px] text-slate-400">#ops-alerts channel</p></div>
              <button type="button" class="toggle" data-on="true" role="switch" aria-checked="true"><span class="knob"></span></button>
            </li>
            <li class="flex items-center justify-between gap-4 py-3">
              <div><p class="text-xs font-semibold text-slate-700 dark:text-slate-200">Anonymous product analytics</p><p class="text-[11px] text-slate-400">Aggregated, no PII</p></div>
              <button type="button" class="toggle" data-on="false" role="switch" aria-checked="false"><span class="knob"></span></button>
            </li>
          </ul>
        </div>

        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-bold text-slate-900 dark:text-white">API &amp; Webhooks</h3>
          <p class="text-[11px] text-slate-400">Programmatic access to this workspace</p>
          <div class="mt-4 space-y-4">
            <div>
              <label class="mb-1.5 block text-xs font-semibold text-slate-600 dark:text-slate-300">Live API key</label>
              <div class="flex gap-2">
                <input type="text" readonly value="nb_live_sk_9f3c8a41d2e7b608" class="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-700 shadow-sm outline-none dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-300">
                <button data-toast="A new API key has been generated and emailed to admins" class="shrink-0 rounded-lg border border-slate-200 px-3 py-2 text-xs font-semibold text-slate-600 transition-colors hover:border-indigo-300 hover:text-indigo-600 dark:border-slate-700 dark:text-slate-300 dark:hover:border-indigo-500/40 dark:hover:text-indigo-300">Regenerate</button>
              </div>
              <p class="mt-1.5 text-[11px] text-slate-400">Last used 14 minutes ago from 203.0.113.24</p>
            </div>
            <div>
              <label class="mb-1.5 block text-xs font-semibold text-slate-600 dark:text-slate-300">Webhook endpoint</label>
              <input type="text" value="https://hooks.acme.example/nimbus/e8f2" class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-xs text-slate-800 shadow-sm outline-none transition-colors focus:border-indigo-400 focus:ring-2 focus:ring-indigo-500/20 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-100">
            </div>
            <button data-toast="API settings saved (simulated)" class="rounded-lg bg-indigo-600 px-4 py-2 text-xs font-bold text-white shadow-sm shadow-indigo-600/30 transition-colors hover:bg-indigo-500">Save changes</button>
          </div>
        </div>

        <div class="rounded-2xl border border-rose-300/60 bg-rose-50/50 p-5 dark:border-rose-500/25 dark:bg-rose-500/5">
          <h3 class="text-sm font-bold text-rose-700 dark:text-rose-300">Danger Zone</h3>
          <p class="text-[11px] text-rose-600/80 dark:text-rose-300/60">Irreversible workspace operations</p>
          <div class="mt-4 flex flex-wrap gap-2">
            <button data-toast="Purging the analytics cache is disabled in this demo" class="rounded-lg border border-rose-300 bg-white px-3 py-2 text-xs font-semibold text-rose-700 transition-colors hover:bg-rose-50 dark:border-rose-500/30 dark:bg-transparent dark:text-rose-300 dark:hover:bg-rose-500/10">Purge analytics cache</button>
            <button data-toast="Workspace deletion is blocked in demo mode" class="rounded-lg bg-rose-600 px-3 py-2 text-xs font-bold text-white shadow-sm shadow-rose-600/30 transition-colors hover:bg-rose-500">Delete workspace</button>
          </div>
        </div>
      </div>
    </section>

    <!-- ══════════════════════════ LAB GUIDE VIEW ══════════════════════════ -->
    <section data-view-panel="lab" class="hidden space-y-6">
      <style>
        .sol-card{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:20px 24px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
        .sol-title{font-size:20px;font-weight:700;color:#0f172a;margin:0}
        .sol-h{font-size:16px;font-weight:700;color:#0f172a;margin:0}
        .sol-text{font-size:14px;line-height:1.65;color:#475569;margin:6px 0 0}
        .sol-step{display:flex;gap:14px;align-items:flex-start}
        .sol-num{flex:0 0 auto;width:34px;height:34px;border-radius:999px;background:#4f46e5;color:#fff;font-weight:700;font-size:15px;display:grid;place-items:center}
        .sol-body{flex:1 1 auto;min-width:0}
        .sol-code{position:relative;margin-top:10px;background:#0f172a;color:#e2e8f0;border-radius:10px;padding:12px 90px 12px 14px;font:13px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-x:auto;white-space:pre;}
        .sol-copy{position:absolute;top:8px;right:8px;font-size:12px;font-weight:600;background:#334155;color:#fff;border:0;border-radius:8px;padding:5px 10px;cursor:pointer}
        .sol-copy:hover{background:#475569}
        .sol-expect{margin-top:10px;font-size:14px;line-height:1.6;color:#334155;background:#f1f5f9;border-radius:10px;padding:10px 14px}
        .sol-expect code{background:#e2e8f0;border-radius:4px;padding:1px 4px;font-size:13px}
        .sol-list{margin:8px 0 0;padding-left:20px;font-size:14px;line-height:1.7;color:#475569}
        .sol-list li{margin-top:4px}
        .sol-done{display:flex;align-items:center;gap:6px;margin-top:12px;font-size:13px;font-weight:600;color:#047857;cursor:pointer;user-select:none}
        .sol-done input{width:16px;height:16px;accent-color:#059669}
        .sol-warn{border-color:#fcd34d;background:#fffbeb}
        .sol-bar{height:8px;border-radius:999px;background:#e2e8f0;overflow:hidden;margin-top:10px}
        .sol-bar > div{height:100%;width:0;background:linear-gradient(90deg,#10b981,#4f46e5);transition:width .4s}
        .dark .sol-card{background:#0f172a;border-color:#1e293b}
        .dark .sol-title,.dark .sol-h{color:#f8fafc}
        .dark .sol-text,.dark .sol-list{color:#94a3b8}
        .dark .sol-expect{background:#1e293b;color:#cbd5e1}
        .dark .sol-expect code{background:#334155}
        .dark .sol-warn{border-color:#92400e;background:rgba(245,158,11,.08)}
        .dark .sol-bar{background:#1e293b}
      </style>

      <!-- intro -->
      <div class="sol-card">
        <h2 class="sol-title">Solution: Walkthrough</h2>
        <p class="sol-text">This lab runs an <strong>old version of PHP</strong> (the programming language this website is built with). PHP has two known bugs that let an attacker run commands on the server. Your only job is to answer one question:</p>
        <p class="sol-text" style="font-size:16px;color:#0f172a;font-weight:600;margin-top:10px">Is this PHP version safe, or does it need an update?</p>
        <p class="sol-text">You will <strong>not</strong> attack anything. Just check the version and the settings, then write down your answer.</p>
        <div class="sol-bar" aria-hidden="true"><div id="sol-bar-fill"></div></div>
        <p class="sol-text" style="font-size:13px"><span id="sol-count">0</span> of 11 steps done <span style="opacity:.7">(saved in this browser)</span></p>
      </div>

      <div class="sol-card sol-warn">
        <p class="sol-h">Before you start</p>
        <ul class="sol-list">
          <li>Use this only on your own computer. Never put this lab on the internet.</li>
          <li>Run the commands in a terminal, in the <code>cvephp</code> folder you downloaded.</li>
          <li>An error message or a crash is <strong>not</strong> a win. You only need to find the version and the settings.</li>
        </ul>
      </div>

      <!-- the two bugs in plain words -->
      <div class="sol-card">
        <p class="sol-h">The two bugs in plain words</p>
        <p class="sol-text">Both bugs are inside PHP itself, not in the dashboard. Both are fixed in the same new versions.</p>

        <div style="margin-top:16px;border-top:1px solid #e2e8f0;padding-top:14px">
          <p class="sol-h">Bug 1: CVE-2026-109618 (memory bug)</p>
          <ul class="sol-list">
            <li><strong>What it is:</strong> PHP runs out of memory while handling a request, and then reads memory that is no longer safe to use.</li>
            <li><strong>Why it matters:</strong> an attacker could use this to take control of the server.</li>
            <li><strong>Setting to look at:</strong> <code>memory_limit</code>. A small limit like 256M makes running out of memory easier.</li>
            <li><strong>Fixed in:</strong> PHP 8.4.27 (and 8.5.12, 8.3.36, 8.2.35).</li>
          </ul>
        </div>

        <div style="margin-top:16px;border-top:1px solid #e2e8f0;padding-top:14px">
          <p class="sol-h">Bug 2: CVE-2026-109619 (leftover data bug)</p>
          <ul class="sol-list">
            <li><strong>What it is:</strong> PHP keeps a pointer to memory it has already freed. A later request on the same worker can then use that old pointer.</li>
            <li><strong>Why it matters:</strong> the same attack risk as bug 1.</li>
            <li><strong>Setting to look at:</strong> <code>session.upload_progress.enabled</code>. When it is <code>On</code>, this bug's path is open.</li>
            <li><strong>Fixed in:</strong> the same versions as bug 1.</li>
          </ul>
        </div>

        <p class="sol-text" style="margin-top:14px"><strong>Simple rule:</strong> if your PHP version is older than the fixed version, the server is at risk from both bugs until you update.</p>
      </div>

      <p class="sol-title" style="font-size:16px;margin:18px 4px 0">Part 1: Get the lab running</p>

      <div class="sol-card" data-step>
        <div class="sol-step">
          <div class="sol-num">1</div>
          <div class="sol-body">
            <p class="sol-h">Install Docker (the box that runs the lab)</p>
            <p class="sol-text">Docker runs the lab in a safe, separate box on your computer. Install Docker Desktop (Windows or Mac) or Docker Engine (Linux). Then open a terminal and check it works:</p><div class="sol-code"><button type="button" class="sol-copy">Copy</button>docker --version</div>            <div class="sol-expect">You should see a line like <code>Docker version 24.0.5</code>. Any version is fine.</div>
            <label class="sol-done"><input type="checkbox" data-step-check="1"> I did this step</label>
          </div>
        </div>
      </div>

      <div class="sol-card" data-step>
        <div class="sol-step">
          <div class="sol-num">2</div>
          <div class="sol-body">
            <p class="sol-h">Start the lab</p>
            <p class="sol-text">In the <code>cvephp</code> folder, run these two lines. The first builds the lab, the second starts it.</p><div class="sol-code"><button type="button" class="sol-copy">Copy</button>docker build -f php2shell-lab/Dockerfile --build-arg PHP_IMAGE=php:8.4.26-fpm-alpine -t php2shell-lab:8.4.26 php2shell-lab
docker run -d --name php2shell-vm --memory=256m --cpus=1 -p 127.0.0.1:8080:80 php2shell-lab:8.4.26</div>            <div class="sol-expect">The second line prints a long code. That means the lab is running.</div>
            <label class="sol-done"><input type="checkbox" data-step-check="2"> I did this step</label>
          </div>
        </div>
      </div>

      <div class="sol-card" data-step>
        <div class="sol-step">
          <div class="sol-num">3</div>
          <div class="sol-body">
            <p class="sol-h">Check the lab answers</p>
            <p class="sol-text">Ask the lab a simple question. Copy this line, or open the link in your browser:</p><div class="sol-code"><button type="button" class="sol-copy">Copy</button>curl -s "http://127.0.0.1:8080/index.php?api=ping"</div>            <div class="sol-expect">You should see <code>"status": "ok"</code>. If not, wait 10 seconds and try again.</div>
            <label class="sol-done"><input type="checkbox" data-step-check="3"> I did this step</label>
          </div>
        </div>
      </div>

      <p class="sol-title" style="font-size:16px;margin:18px 4px 0">Part 2: Find out which PHP version is running</p>

      <div class="sol-card" data-step>
        <div class="sol-step">
          <div class="sol-num">4</div>
          <div class="sol-body">
            <p class="sol-h">Read the PHP version</p>
            <p class="sol-text">PHP is the programming language the website is built with. Both bugs live inside PHP, so the version matters most.</p><div class="sol-code"><button type="button" class="sol-copy">Copy</button>curl -s "http://127.0.0.1:8080/index.php?api=ping"</div>            <div class="sol-expect">Look for <code>"php": "8.4.26"</code> and <code>"sapi": "fpm-fcgi"</code>. Write both down. <code>fpm-fcgi</code> means PHP is serving the website, which is the case the bugs care about.</div>
            <label class="sol-done"><input type="checkbox" data-step-check="4"> I did this step</label>
          </div>
        </div>
      </div>

      <div class="sol-card" data-step>
        <div class="sol-step">
          <div class="sol-num">5</div>
          <div class="sol-body">
            <p class="sol-h">Check whether that version is fixed</p>
            <p class="sol-text">Both bugs are fixed in these versions (or any newer one): <strong>8.4.27</strong>, 8.5.12, 8.3.36, 8.2.35.</p>            <p class="sol-text">Our lab runs <strong>8.4.26</strong>. That is lower than 8.4.27, so the lab is <strong>NOT patched</strong> for <strong>both</strong> bugs.</p>            <div class="sol-expect">Simple rule: lower number than the fixed one means not patched.</div>
            <label class="sol-done"><input type="checkbox" data-step-check="5"> I did this step</label>
          </div>
        </div>
      </div>

      <p class="sol-title" style="font-size:16px;margin:18px 4px 0">Part 3: Bug 1, CVE-2026-109618 (the memory bug)</p>

      <div class="sol-card" data-step>
        <div class="sol-step">
          <div class="sol-num">6</div>
          <div class="sol-body">
            <p class="sol-h">Check the memory limit</p>
            <p class="sol-text">Bug 1 happens when PHP runs out of memory. The memory limit is the cap on how much memory one page can use. A small cap makes running out easier, so we check it.</p><div class="sol-code"><button type="button" class="sol-copy">Copy</button>docker exec php2shell-vm php -i | grep -E "^(memory_limit|post_max_size)"</div><ul class="sol-list"><li><code>memory_limit => 256M</code>: the cap is small, so bug 1 is possible.</li><li><code>post_max_size => 24M</code>: how big a form upload can be. Bigger uploads give more room to fill memory.</li></ul>            <p class="sol-text"><strong>Result for bug 1:</strong> the setting is present, and the version is not fixed. Bug 1 is <strong>possible</strong> here.</p>
            <label class="sol-done"><input type="checkbox" data-step-check="6"> I did this step</label>
          </div>
        </div>
      </div>

      <p class="sol-title" style="font-size:16px;margin:18px 4px 0">Part 4: Bug 2, CVE-2026-109619 (the leftover data bug)</p>

      <div class="sol-card" data-step>
        <div class="sol-step">
          <div class="sol-num">7</div>
          <div class="sol-body">
            <p class="sol-h">Check the upload progress feature</p>
            <p class="sol-text">Bug 2 needs a feature called upload progress. It is used to show how far a file upload has got. When it is on, the bug's path is open.</p><div class="sol-code"><button type="button" class="sol-copy">Copy</button>docker exec php2shell-vm php -i | grep "^session.upload_progress.enabled"</div>            <div class="sol-expect">You should see <code>session.upload_progress.enabled => On</code>.</div>            <p class="sol-text"><strong>Result:</strong> the feature is on, so bug 2's path is open.</p>
            <label class="sol-done"><input type="checkbox" data-step-check="7"> I did this step</label>
          </div>
        </div>
      </div>

      <div class="sol-card" data-step>
        <div class="sol-step">
          <div class="sol-num">8</div>
          <div class="sol-body">
            <p class="sol-h">Check how long PHP workers live</p>
            <p class="sol-text">A worker is a helper process that handles visitors. Bug 2 needs a worker to keep old data around for the next request. If workers never restart, the old data stays. We check the restart setting:</p><div class="sol-code"><button type="button" class="sol-copy">Copy</button>docker exec php2shell-vm sh -c "grep -R pm.max_requests /usr/local/etc/php-fpm.d/"</div>            <div class="sol-expect">You should see <code>pm.max_requests = 0</code>. Zero means workers never restart, so the old data stays around.</div>            <p class="sol-text"><strong>Result for bug 2:</strong> the feature is on and workers never restart. Bug 2 is <strong>possible</strong> here.</p>
            <label class="sol-done"><input type="checkbox" data-step-check="8"> I did this step</label>
          </div>
        </div>
      </div>

      <p class="sol-title" style="font-size:16px;margin:18px 4px 0">Part 5: Prove the fix works</p>

      <div class="sol-card" data-step>
        <div class="sol-step">
          <div class="sol-num">9</div>
          <div class="sol-body">
            <p class="sol-h">Build a fixed copy to compare (recommended)</p>
            <p class="sol-text">This builds the same lab, but with the fixed PHP version. Only the version changes, so you can see the difference.</p><div class="sol-code"><button type="button" class="sol-copy">Copy</button>docker build -f php2shell-lab/Dockerfile --build-arg PHP_IMAGE=php:8.4.27-fpm-alpine -t php2shell-lab:8.4.27 php2shell-lab
docker run -d --name php2shell-patched --memory=256m --cpus=1 -p 127.0.0.1:8081:80 php2shell-lab:8.4.27
curl -s "http://127.0.0.1:8081/index.php?api=ping"</div>            <div class="sol-expect">The last line should show <code>"php": "8.4.27"</code>. That version is fixed for both bugs.</div>
            <label class="sol-done"><input type="checkbox" data-step-check="9"> I did this step</label>
          </div>
        </div>
      </div>

      <p class="sol-title" style="font-size:16px;margin:18px 4px 0">Part 6: Write your answer</p>

      <div class="sol-card" data-step>
        <div class="sol-step">
          <div class="sol-num">10</div>
          <div class="sol-body">
            <p class="sol-h">Write the report (copy and fill in)</p>
            <p class="sol-text">Use this sentence and put in your own numbers:</p><div class="sol-code"><button type="button" class="sol-copy">Copy</button>Our lab runs PHP 8.4.26 (fpm-fcgi). The fixed version is 8.4.27, so it is NOT patched for CVE-2026-109618 (memory bug) or CVE-2026-109619 (leftover data bug). Found: memory_limit 256M, post_max_size 24M, session.upload_progress On, pm.max_requests 0. Recommendation: update PHP to 8.4.27 or newer and restart the workers. We did not attack the system.</div>
            <label class="sol-done"><input type="checkbox" data-step-check="10"> I did this step</label>
          </div>
        </div>
      </div>

      <p class="sol-title" style="font-size:16px;margin:18px 4px 0">Part 7: Clean up</p>

      <div class="sol-card" data-step>
        <div class="sol-step">
          <div class="sol-num">11</div>
          <div class="sol-body">
            <p class="sol-h">Stop and remove the lab</p>
            <p class="sol-text">Stop and remove both boxes when you are finished:</p><div class="sol-code"><button type="button" class="sol-copy">Copy</button>docker rm -f php2shell-vm php2shell-patched</div>
            <label class="sol-done"><input type="checkbox" data-step-check="11"> I did this step</label>
          </div>
        </div>
      </div>

      <p class="sol-text" style="text-align:center">Want every detail? The full guide is <code>WALKTHROUGH.md</code> in the repository.</p>
    </section>
  </main>

  <!-- ══════════════════════════════  FOOTER  ══════════════════════════════ -->
  <footer class="border-t border-slate-200 px-6 py-4 dark:border-slate-800">
    <div class="mx-auto flex max-w-[1440px] flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
      <span>© 2026 Nimbus Analytics, Inc. · SOC 2 Type II · ISO 27001</span>
      <span class="font-mono">build 2026.10.1 · <?= e(PHP_SAPI) ?> · PHP <?= e(PHP_VERSION) ?> · us-east-1</span>
    </div>
  </footer>
</div>

<!-- toast -->
<div id="toast" class="pointer-events-none fixed bottom-5 right-5 z-50 translate-y-2 opacity-0 transition-all duration-300">
  <div class="flex items-center gap-2.5 rounded-xl border border-slate-200 bg-white px-4 py-3 text-xs font-medium text-slate-700 shadow-xl dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
    <span class="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-emerald-100 text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-400">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="h-3 w-3"><path d="M5 13l4 4L19 7"/></svg>
    </span>
    <span id="toastMsg">Done</span>
  </div>
</div>

<script>
window.__BOOT__ = <?= json_encode($boot, JSON_UNESCAPED_SLASHES | JSON_HEX_TAG) ?>;
</script>
<script>
/* ══════════════════════ Nimbus dashboard runtime (vanilla JS) ══════════════════════ */
(function () {
  'use strict';

  var $  = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var esc = function (s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  };
  var nf = new Intl.NumberFormat('en-US');
  var BOOT = window.__BOOT__;

  try { console.info('[nimbus-analytics] runtime: PHP ' + BOOT.php + ' (' + BOOT.sapi + ')'); } catch (e) {}

  /* ── theme ─────────────────────────────────────────────── */
  $('#themeToggle').addEventListener('click', function () {
    var dark = document.documentElement.classList.toggle('dark');
    try { localStorage.setItem('nimbus-theme', dark ? 'dark' : 'light'); } catch (e) {}
    window.dispatchEvent(new Event('themechange'));
  });

  /* ── mobile nav ────────────────────────────────────────── */
  var sidebar = $('#sidebar'), scrim = $('#scrim');
  function closeNav() { sidebar.classList.add('-translate-x-full'); scrim.classList.add('hidden'); }
  $('#navToggle').addEventListener('click', function () {
    sidebar.classList.toggle('-translate-x-full'); scrim.classList.toggle('hidden');
  });
  scrim.addEventListener('click', closeNav);

  /* ── view switching ────────────────────────────────────── */
  var TITLES = {
    dashboard:    ['Dashboard',           'Nimbus Analytics / Overview'],
    analytics:    ['Analytics',           'Nimbus Analytics / Analytics'],
    logs:         ['System Logs',         'Nimbus Analytics / Operations / Logs'],
    integrations: ['Integrations',        'Nimbus Analytics / Platform / Integrations'],
    runtime:      ['Runtime Environment', 'Nimbus Analytics / Platform / Runtime'],
    settings:     ['Settings',            'Nimbus Analytics / Platform / Settings'],
    lab:          ['Solution',            'Nimbus Analytics / Security Lab / Solution']
  };
  var NAV_ACTIVE = 'nav-link group flex items-center gap-3 rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white shadow-sm shadow-indigo-600/30 transition-colors';
  var NAV_IDLE   = 'nav-link group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/70 dark:hover:text-white';
  var NAV_LAB_IDLE = 'nav-link group flex items-center gap-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm font-semibold text-rose-700 transition-colors hover:bg-rose-100 dark:border-rose-500/25 dark:bg-rose-500/10 dark:text-rose-300 dark:hover:bg-rose-500/15';
  function show(view) {
    $$('[data-view-panel]').forEach(function (p) { p.classList.toggle('hidden', p.dataset.viewPanel !== view); });
    $$('.nav-link').forEach(function (a) {
      if (a.dataset.view === view) a.className = NAV_ACTIVE;
      else if (a.dataset.view === 'lab') a.className = NAV_LAB_IDLE;
      else a.className = NAV_IDLE;
    });
    var t = TITLES[view] || ['—', ''];
    $('#pageTitle').textContent = t[0];
    $('#pageCrumb').textContent = t[1];
    if (view === 'analytics' && charts && charts.sessions) { charts.sessions.resize(); }
  }
  $$('.nav-link').forEach(function (a) {
    a.addEventListener('click', function (ev) {
      ev.preventDefault();
      var v = a.dataset.view;
      if (v === 'logs') {
        /* the operational log console lives on the dashboard — jump to it */
        show('dashboard');
        var card = $('#logsCard');
        if (card && card.scrollIntoView) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else {
        show(v);
      }
      if (window.innerWidth < 1024) closeNav();
    });
  });

  /* ── solution walkthrough: copy buttons + saved checkboxes ── */
  (function () {
    var KEY = 'sol-steps-done';
    var checks = $$('[data-step-check]');
    function load() {
      var saved = {};
      try { saved = JSON.parse(localStorage.getItem(KEY) || '{}'); } catch (e) {}
      checks.forEach(function (c) { c.checked = !!saved[c.dataset.stepCheck]; });
      update();
    }
    function update() {
      var done = checks.filter(function (c) { return c.checked; }).length;
      var total = checks.length || 1;
      var count = document.getElementById('sol-count');
      var fill = document.getElementById('sol-bar-fill');
      if (count) count.textContent = done;
      if (fill) fill.style.width = Math.round(done / total * 100) + '%';
    }
    checks.forEach(function (c) {
      c.addEventListener('change', function () {
        var data = {};
        checks.forEach(function (x) { data[x.dataset.stepCheck] = x.checked; });
        try { localStorage.setItem(KEY, JSON.stringify(data)); } catch (e) {}
        update();
      });
    });
    $$('.sol-copy').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var text = btn.parentElement.textContent.replace(/^Copy/, '').trim();
        var done = function () { btn.textContent = 'Copied'; setTimeout(function () { btn.textContent = 'Copy'; }, 1200); };
        if (navigator.clipboard) { navigator.clipboard.writeText(text).then(done, function () { toast('Copy failed, select the text manually'); }); }
        else { toast('Copy failed, select the text manually'); }
      });
    });
    load();
    if (new URLSearchParams(window.location.search).get('view') === 'lab') show('lab');
  })();

  /* ── deep links for the other views: ?view=runtime etc. ── */
  (function () {
    var requested = new URLSearchParams(window.location.search).get('view');
    if (!requested || requested === 'lab' || !TITLES[requested]) return;
    show(requested === 'logs' ? 'dashboard' : requested);
  })();

  /* ── canvas chart engine ───────────────────────────────── */
  function hexA(hex, a) {
    var n = parseInt(hex.slice(1), 16);
    return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
  }
  function createChart(canvas, cfg) {
    if (!canvas) return { setData: function () {}, resize: function () {} };
    var ctx = canvas.getContext('2d');
    var labels = cfg.labels.slice();
    var series = cfg.series.map(function (s) { return s.data.slice(); });
    var W = 300, H = cfg.height, DPR = 1, raf = null;

    function isDark() { return document.documentElement.classList.contains('dark'); }

    function resize() {
      var box = canvas.parentElement.getBoundingClientRect();
      DPR = window.devicePixelRatio || 1;
      W = Math.max(80, box.width);
      canvas.width = Math.round(W * DPR);
      canvas.height = Math.round(H * DPR);
      canvas.style.width = W + 'px';
      canvas.style.height = H + 'px';
      draw();
    }

    function draw() {
      var P = { l: 46, r: 14, t: 14, b: 26 };
      var iw = W - P.l - P.r, ih = H - P.t - P.b;
      var dark = isDark();
      var grid = dark ? 'rgba(148,163,184,0.13)' : 'rgba(100,116,139,0.16)';
      var txt  = dark ? '#7d8db0' : '#64748b';
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      ctx.clearRect(0, 0, W, H);
      ctx.font = '11px ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif';

      /* grid + y labels (scale of the first series) */
      var s0 = series[0];
      var min0 = Math.min.apply(null, s0), max0 = Math.max.apply(null, s0), span0 = (max0 - min0) || 1;
      for (var g = 0; g <= 4; g++) {
        var gy = P.t + ih * g / 4;
        ctx.strokeStyle = grid; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(P.l, gy); ctx.lineTo(W - P.r, gy); ctx.stroke();
        ctx.fillStyle = txt; ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
        var gv = Math.round(max0 - span0 * g / 4);
        ctx.fillText(cfg.series[0].fmt ? cfg.series[0].fmt(gv) : String(gv), P.l - 8, gy);
      }
      /* x labels */
      ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic';
      var le = cfg.labelEvery || 6;
      for (var i = 0; i < labels.length; i++) {
        if (i % le === 0 || i === labels.length - 1) {
          ctx.fillText(labels[i], P.l + iw * i / (labels.length - 1), H - 8);
        }
      }
      /* series */
      cfg.series.forEach(function (s, si) {
        var data = series[si];
        var n = data.length;
        var min = Math.min.apply(null, data), max = Math.max.apply(null, data), span = (max - min) || 1;
        var x = function (i) { return P.l + iw * i / (n - 1); };
        var y = function (v) { return P.t + ih * (0.08 + (1 - (v - min) / span) * 0.82); };
        /* smooth path */
        function path() {
          ctx.beginPath();
          ctx.moveTo(x(0), y(data[0]));
          for (var k = 1; k < n; k++) {
            var x0 = x(k - 1), y0 = y(data[k - 1]), x1 = x(k), y1 = y(data[k]);
            ctx.quadraticCurveTo(x0, y0, (x0 + x1) / 2, (y0 + y1) / 2);
          }
          ctx.lineTo(x(n - 1), y(data[n - 1]));
        }
        if (s.area) {
          var grad = ctx.createLinearGradient(0, P.t, 0, P.t + ih);
          grad.addColorStop(0, hexA(s.color, 0.26));
          grad.addColorStop(1, hexA(s.color, 0.01));
          path();
          ctx.lineTo(x(n - 1), P.t + ih); ctx.lineTo(x(0), P.t + ih); ctx.closePath();
          ctx.fillStyle = grad; ctx.fill();
        }
        path();
        ctx.strokeStyle = s.color; ctx.lineWidth = 2.2; ctx.lineJoin = 'round'; ctx.lineCap = 'round';
        ctx.setLineDash(s.dash ? [6, 5] : []);
        ctx.stroke();
        ctx.setLineDash([]);
        /* live dot */
        var lx = x(n - 1), ly = y(data[n - 1]);
        ctx.fillStyle = hexA(s.color, 0.18);
        ctx.beginPath(); ctx.arc(lx, ly, 7, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = s.color;
        ctx.beginPath(); ctx.arc(lx, ly, 3.4, 0, Math.PI * 2); ctx.fill();
      });
    }

    function setData(newLabels, arrays) {
      var from = series.map(function (s) { return s.slice(); });
      var to = arrays;
      labels = newLabels.slice();
      var t0 = performance.now(), D = 600;
      if (raf) cancelAnimationFrame(raf);
      function step(t) {
        var k = Math.min(1, (t - t0) / D);
        var e = 1 - Math.pow(1 - k, 3);
        series = from.map(function (s, si) {
          return s.map(function (v, i) { return v + ((to[si][i] - v) * e); });
        });
        draw();
        if (k < 1) raf = requestAnimationFrame(step);
      }
      raf = requestAnimationFrame(step);
    }

    window.addEventListener('resize', resize);
    window.addEventListener('themechange', draw);
    if (window.ResizeObserver) { new ResizeObserver(resize).observe(canvas.parentElement); }
    resize();
    return { setData: setData, resize: resize };
  }

  var charts = {};
  charts.revenue = createChart($('#chartRevenue'), {
    height: 270, labels: BOOT.series.labels, labelEvery: 6,
    series: [
      { data: BOOT.series.revenue,  color: '#6366f1', area: true, fmt: function (v) { return '$' + v + 'k'; } },
      { data: BOOT.series.sessions, color: '#10b981', dash: true }
    ]
  });
  charts.sessions = createChart($('#chartSessions'), {
    height: 280, labels: BOOT.series.labels, labelEvery: 6,
    series: [
      { data: BOOT.series.sessions, color: '#10b981', area: true, fmt: function (v) { return nf.format(v); } }
    ]
  });

  /* ── sparkline svg updater ─────────────────────────────── */
  function spark(id, data) {
    var svg = document.getElementById(id);
    if (!svg) return;
    var min = Math.min.apply(null, data), max = Math.max.apply(null, data), span = (max - min) || 1;
    var pts = data.map(function (v, i) {
      return [(i / (data.length - 1)) * 112, 29 - ((v - min) / span) * 26];
    });
    var str = pts.map(function (p) { return p[0].toFixed(1) + ',' + p[1].toFixed(1); }).join(' ');
    svg.innerHTML = '<polygon points="0,32 ' + str + ' 112,32" fill="currentColor" fill-opacity="0.12"/>' +
      '<polyline points="' + str + '" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>';
  }

  /* ── operational log stream ────────────────────────────── */
  var logBody = $('#logBody');
  var seen = {};
  $$('#logBody tr').forEach(function (r) { seen[r.dataset.id] = true; });
  var filter = 'all';

  function logRow(l) {
    var lvl = String(l.level || 'info').toLowerCase();
    var tr = document.createElement('tr');
    tr.dataset.id = l.id;
    tr.dataset.level = lvl;
    tr.className = 'rowin border-b border-slate-100 transition-colors hover:bg-slate-50/80 dark:border-slate-800/60 dark:hover:bg-slate-800/40';
    tr.innerHTML =
      '<td class="whitespace-nowrap px-3 py-2.5 font-mono text-xs text-slate-500 dark:text-slate-400">' + esc(l.time) + '</td>' +
      '<td class="whitespace-nowrap px-3 py-2.5"><span class="lvl lvl-' + esc(lvl) + '">' + esc(l.level) + '</span></td>' +
      '<td class="whitespace-nowrap px-3 py-2.5 font-mono text-xs font-medium text-indigo-600 dark:text-indigo-400">' + esc(l.service) + '</td>' +
      '<td class="px-3 py-2.5 text-xs text-slate-600 dark:text-slate-300">' + esc(l.msg) + '</td>' +
      '<td class="whitespace-nowrap px-3 py-2.5 font-mono text-[11px] text-slate-400 dark:text-slate-500">' + esc(l.trace) + '</td>';
    return tr;
  }

  $$('#logFilters button').forEach(function (b) {
    b.addEventListener('click', function () {
      filter = b.dataset.filter;
      $$('#logFilters button').forEach(function (x) { x.classList.toggle('pill-active', x === b); });
      $$('#logBody tr').forEach(function (r) {
        r.classList.toggle('hidden', filter !== 'all' && r.dataset.level !== filter);
      });
    });
  });

  /* ── live number ticking ───────────────────────────────── */
  function setNum(sel, val) {
    var el = $(sel);
    if (!el) return;
    var next = String(val);
    if (el.textContent === next) return;
    el.textContent = next;
    el.classList.remove('tick');
    void el.offsetWidth;
    el.classList.add('tick');
  }

  /* ── polling loop ──────────────────────────────────────── */
  function apply(j) {
    setNum('#m-sessions', nf.format(j.sessions));
    setNum('#m-rps', nf.format(j.rps));
    setNum('#m-p95', j.p95_ms);
    setNum('#m-err', Number(j.error_rate).toFixed(2));
    if (j.spark) {
      spark('spk-sessions', j.spark.sessions);
      spark('spk-p95', j.spark.p95);
    }
    if (j.point) {
      BOOT.series.labels   = BOOT.series.labels.slice(1).concat(j.point.label);
      BOOT.series.revenue  = BOOT.series.revenue.slice(1).concat(j.point.revenue);
      BOOT.series.sessions = BOOT.series.sessions.slice(1).concat(j.point.sessions);
      charts.revenue.setData(BOOT.series.labels, [BOOT.series.revenue, BOOT.series.sessions]);
      charts.sessions.setData(BOOT.series.labels, [BOOT.series.sessions]);
    }
    var added = 0;
    (j.logs || []).forEach(function (l) {
      if (seen[l.id]) return;
      seen[l.id] = true;
      var row = logRow(l);
      if (filter !== 'all' && row.dataset.level !== filter) row.classList.add('hidden');
      logBody.insertBefore(row, logBody.firstChild);
      added++;
    });
    while (logBody.children.length > 42) {
      delete seen[logBody.lastElementChild.dataset.id];
      logBody.removeChild(logBody.lastElementChild);
    }
    $('#logCount').textContent = logBody.children.length + ' events buffered' + (added ? ' · ' + added + ' new' : '');
    $('#syncTime').textContent = new Date().toLocaleTimeString();
  }

  function poll() {
    fetch('index.php?api=stats', { headers: { Accept: 'application/json' } })
      .then(function (r) { if (!r.ok) throw new Error('http ' + r.status); return r.json(); })
      .then(apply)
      .catch(function () { /* transient — keep last good state */ });
  }
  setInterval(poll, BOOT.pollMs || 4000);

  /* ── toggles & toasts ──────────────────────────────────── */
  $$('.toggle').forEach(function (t) {
    t.addEventListener('click', function () {
      t.dataset.on = t.dataset.on === 'true' ? 'false' : 'true';
      t.setAttribute('aria-checked', t.dataset.on);
    });
  });

  var toastTimer = null;
  function toast(msg) {
    $('#toastMsg').textContent = msg;
    var box = $('#toast');
    box.classList.remove('translate-y-2', 'opacity-0');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { box.classList.add('translate-y-2', 'opacity-0'); }, 2800);
  }
  $$('[data-toast]').forEach(function (b) {
    b.addEventListener('click', function () { toast(b.dataset.toast || 'Saved'); });
  });
})();
</script>
</body>
</html>

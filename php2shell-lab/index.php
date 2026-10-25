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

/* ===================================================== walkthrough === */

/** Very small markdown → HTML for WALKTHROUGH.md (headings, lists, code, tables, details, links, bold, inline code). */
function walkthrough_md_to_html(string $md): string
{
    // Split into lines, handle fenced code blocks first
    $lines = explode("\n", $md);
    $out = '';
    $inCode = false;
    $codeLang = '';
    $codeBuf = '';
    $inTable = false;
    $tableRows = [];
    $listStack = []; // stack of 'ul'|'ol'

    $flushTable = function() use (&$out, &$inTable, &$tableRows) {
        if (!$inTable || empty($tableRows)) { $inTable = false; $tableRows = []; return; }
        $out .= '<div class="overflow-x-auto my-4 rounded-xl border border-slate-200 dark:border-slate-700"><table class="w-full text-left text-xs"><thead class="bg-slate-50 dark:bg-slate-800 text-[11px] uppercase tracking-wider text-slate-400"><tr>';
        $header = $tableRows[0];
        foreach ($header as $h) { $out .= '<th class="px-3 py-2 font-semibold">' . md_inline($h) . '</th>'; }
        $out .= '</tr></thead><tbody class="divide-y divide-slate-100 dark:divide-slate-800">';
        for ($i = 2; $i < count($tableRows); $i++) { // skip separator row
            $out .= '<tr class="hover:bg-slate-50/80 dark:hover:bg-slate-800/40">';
            foreach ($tableRows[$i] as $c) { $out .= '<td class="px-3 py-2 text-slate-700 dark:text-slate-300">' . md_inline($c) . '</td>'; }
            $out .= '</tr>';
        }
        $out .= '</tbody></table></div>';
        $inTable = false; $tableRows = [];
    };
    $closeLists = function() use (&$out, &$listStack) {
        while (!empty($listStack)) { $tag = array_pop($listStack); $out .= "</$tag>"; }
    };

    for ($i = 0; $i < count($lines); $i++) {
        $line = $lines[$i];
        $trim = trim($line);

        // Fenced code block
        if (preg_match('/^```(\w*)/', $trim, $m)) {
            if (!$inCode) { $inCode = true; $codeLang = $m[1] ?? ''; $codeBuf = ''; $flushTable(); $closeLists(); }
            else {
                $inCode = false;
                $out .= '<div class="my-4 overflow-hidden rounded-xl border border-slate-200 dark:border-slate-700">'
                    . '<div class="flex items-center justify-between bg-slate-50 px-4 py-2 dark:bg-slate-800"><span class="font-mono text-[11px] font-semibold text-slate-500">' . e($codeLang ?: 'bash') . '</span>'
                    . '<button type="button" onclick="copyCode(this)" data-code="' . e($codeBuf) . '" class="copy-btn rounded-full border border-slate-200 bg-white px-3 py-1 text-[11px] font-semibold text-slate-600 hover:border-indigo-300 hover:text-indigo-600 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-300">Copy</button></div>'
                    . '<pre class="overflow-x-auto bg-slate-950 p-4 font-mono text-xs leading-relaxed text-slate-200"><code>' . e(rtrim($codeBuf)) . '</code></pre></div>';
                $codeBuf = '';
            }
            continue;
        }
        if ($inCode) { $codeBuf .= $line . "\n"; continue; }

        // Table detection: | ... | lines
        if (preg_match('/^\|.*\|$/', $trim)) {
            if (!$inTable) { $flushTable(); $inTable = true; $tableRows = []; }
            $cells = array_map('trim', explode('|', trim($trim, '|')));
            $tableRows[] = $cells;
            // If next line isn't table, flush
            $next = isset($lines[$i+1]) ? trim($lines[$i+1]) : '';
            if (!preg_match('/^\|.*\|$/', $next)) { $flushTable(); }
            continue;
        }

        if ($trim === '---' || $trim === '***' || $trim === '___') { $flushTable(); $closeLists(); $out .= '<hr class="my-6 border-slate-200 dark:border-slate-700">'; continue; }
        if ($trim === '') { $flushTable(); continue; }

        // Details/summary (keep as is but styled)
        if (preg_match('/^<details>/i', $trim)) { $flushTable(); $closeLists(); $out .= '<details class="my-3 rounded-xl border border-slate-200 bg-slate-50 p-3 dark:border-slate-700 dark:bg-slate-800/40">'; continue; }
        if (preg_match('/^<\/details>/i', $trim)) { $out .= '</details>'; continue; }
        if (preg_match('/^<summary>(.*)<\/summary>/i', $trim, $mm)) { $out .= '<summary class="cursor-pointer list-inside text-xs font-bold text-indigo-600 dark:text-indigo-400">' . md_inline($mm[1]) . '</summary>'; continue; }

        // Headings
        if (preg_match('/^(#{1,6})\s+(.*)$/', $trim, $mm)) {
            $flushTable(); $closeLists();
            $lvl = strlen($mm[1]);
            $text = $mm[2];
            // strip anchor {#...} if any
            $id = strtolower(preg_replace('/[^a-z0-9]+/', '-', trim(strip_tags($text))));
            $id = trim($id, '-');
            $cls = $lvl === 1 ? 'mt-8 text-2xl font-bold tracking-tight text-slate-900 dark:text-white' : ($lvl === 2 ? 'mt-8 text-lg font-bold tracking-tight text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-2' : ($lvl === 3 ? 'mt-6 text-sm font-bold text-slate-900 dark:text-white' : 'mt-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-300'));
            $out .= "<h$lvl id=\"$id\" class=\"$cls\">" . md_inline($text) . "</h$lvl>";
            continue;
        }

        // Blockquote
        if (preg_match('/^>\s*(.*)$/', $trim, $mm)) {
            $flushTable(); $closeLists();
            $content = $mm[1];
            // collect consecutive blockquotes
            $bq = $content;
            while ($i+1 < count($lines) && preg_match('/^>\s*(.*)$/', trim($lines[$i+1]), $mm2)) { $bq .= '<br>' . $mm2[1]; $i++; }
            $out .= '<blockquote class="my-4 border-l-4 border-indigo-300 bg-indigo-50 px-4 py-3 text-xs leading-relaxed text-indigo-900 dark:border-indigo-500/40 dark:bg-indigo-500/10 dark:text-indigo-200">' . md_inline($bq) . '</blockquote>';
            continue;
        }

        // Lists
        if (preg_match('/^(\d+)\.\s+(.*)$/', $trim, $mm)) {
            if (empty($listStack) || end($listStack) !== 'ol') { $flushTable(); $out .= '<ol class="my-3 list-decimal space-y-2 pl-5 text-xs leading-relaxed text-slate-700 dark:text-slate-300">'; $listStack[] = 'ol'; }
            $out .= '<li>' . md_inline($mm[2]) . '</li>';
            // close if next isn't list item
            $next = isset($lines[$i+1]) ? trim($lines[$i+1]) : '';
            if (!preg_match('/^(\d+)\.\s+/', $next) && !preg_match('/^[-*]\s+/', $next) && $next !== '') {
                // keep open if next is indented continuation? simple: close on blank or non-list
                if ($next === '' || !preg_match('/^[-*\d]/', $next)) { /* keep for now, will close on flush */ }
            }
            if ($next === '' || (!preg_match('/^(\d+)\.\s+/', $next) && !preg_match('/^[-*]\s+/', $next))) {
                // peek further: if next blank then non-list, close
            }
            continue;
        }
        if (preg_match('/^[-*]\s+(.*)$/', $trim, $mm)) {
            // checkbox variant
            if (preg_match('/^\[ \]\s+(.*)$/', $mm[1], $mm2) || preg_match('/^\[x\]\s+(.*)$/i', $mm[1], $mm2)) {
                if (empty($listStack) || end($listStack) !== 'ul') { $flushTable(); $out .= '<ul class="my-3 space-y-2 pl-1 text-xs leading-relaxed text-slate-700 dark:text-slate-300">'; $listStack[] = 'ul'; }
                $checked = stripos($mm[1], '[x]') === 0 ? 'checked' : '';
                $out .= '<li class="flex items-start gap-2"><input type="checkbox" class="mt-0.5 h-3.5 w-3.5 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500" ' . $checked . ' disabled><span>' . md_inline($mm2[1]) . '</span></li>';
            } else {
                if (empty($listStack) || end($listStack) !== 'ul') { $flushTable(); $out .= '<ul class="my-3 list-disc space-y-1.5 pl-5 text-xs leading-relaxed text-slate-700 dark:text-slate-300">'; $listStack[] = 'ul'; }
                $out .= '<li>' . md_inline($mm[1]) . '</li>';
            }
            continue;
        }

        // Paragraph
        $flushTable();
        // close lists if next line is not a list and we have open lists and current line is not list continuation
        if (!empty($listStack) && $trim !== '' && !preg_match('/^[-*\d]/', $trim)) {
            // if this is paragraph, close lists before paragraph
            $closeLists();
        }
        $out .= '<p class="my-3 text-xs leading-relaxed text-slate-700 dark:text-slate-300">' . md_inline($trim) . '</p>';
    }
    $closeLists();
    return $out;
}

function md_inline(string $s): string
{
    // escape first, then restore markdown constructs
    $s = htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    // inline code `code`
    $s = preg_replace_callback('/`([^`]+)`/', function($m){ return '<code class="rounded bg-slate-100 px-1 py-0.5 font-mono text-[11px] text-slate-800 dark:bg-slate-800 dark:text-slate-200">' . $m[1] . '</code>'; }, $s);
    // bold **text**
    $s = preg_replace('/\*\*([^*]+)\*\*/', '<strong class="font-bold text-slate-900 dark:text-white">$1</strong>', $s);
    // italic *text* or _text_
    $s = preg_replace('/\*([^*]+)\*/', '<em>$1</em>', $s);
    // links [text](url)
    $s = preg_replace_callback('/\[([^\]]+)\]\(([^)]+)\)/', function($m){
        $url = $m[2];
        $text = $m[1];
        $isExternal = str_starts_with($url, 'http');
        $target = $isExternal ? ' target="_blank" rel="noopener noreferrer"' : '';
        return '<a href="' . htmlspecialchars($url, ENT_QUOTES) . '"' . $target . ' class="font-medium text-indigo-600 hover:underline dark:text-indigo-400">' . $text . '</a>';
    }, $s);
    return $s;
}

function walkthrough_file_html(): string
{
    $candidates = [__DIR__ . '/../WALKTHROUGH.md', __DIR__ . '/WALKTHROUGH.md', '/var/www/html/WALKTHROUGH.md', 'WALKTHROUGH.md'];
    $content = null;
    foreach ($candidates as $p) {
        if (is_file($p) && is_readable($p)) { $content = @file_get_contents($p); if ($content !== false) break; }
    }
    if ($content === null || trim($content) === '') {
        return '<div class="rounded-xl border border-amber-300 bg-amber-50 p-4 text-xs leading-relaxed text-amber-900 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-200">WALKTHROUGH.md not found in image. Rebuild with <code class="font-mono">COPY WALKTHROUGH.md /var/www/html/WALKTHROUGH.md</code> in Dockerfile, or view it in the repo at <code class="font-mono">WALKTHROUGH.md</code>. The beginner guide below still walks you through every step.</div>';
    }
    return walkthrough_md_to_html($content);
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

// Raw WALKTHROUGH.md download (for beginner tab and offline reading)
if (isset($_GET['walkthrough']) && $_GET['walkthrough'] === 'raw') {
    $candidates = [__DIR__ . '/../WALKTHROUGH.md', __DIR__ . '/WALKTHROUGH.md', '/var/www/html/WALKTHROUGH.md', 'WALKTHROUGH.md'];
    foreach ($candidates as $p) {
        if (is_file($p) && is_readable($p)) {
            header('Content-Type: text/markdown; charset=utf-8');
            header('Content-Disposition: inline; filename="WALKTHROUGH.md"');
            readfile($p);
            exit;
        }
    }
    http_response_code(404);
    header('Content-Type: text/plain');
    echo "WALKTHROUGH.md not found in image. Rebuild with COPY WALKTHROUGH.md included.";
    exit;
}

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
      <!-- hero -->
      <div class="overflow-hidden rounded-2xl border border-rose-300 bg-gradient-to-br from-rose-50 via-white to-indigo-50 shadow-sm dark:border-rose-500/25 dark:from-rose-500/10 dark:via-slate-900 dark:to-indigo-500/10">
        <div class="px-6 py-6 sm:px-8 sm:py-7">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div class="min-w-0">
              <div class="flex flex-wrap items-center gap-2">
                <span class="inline-flex items-center gap-1.5 rounded-full bg-rose-600 px-2.5 py-1 text-[11px] font-bold text-white"><span class="h-1.5 w-1.5 rounded-full bg-white animate-ping"></span> VULNERABLE LAB</span>
                <span class="inline-flex items-center gap-1.5 rounded-full bg-amber-100 px-2.5 py-1 text-[11px] font-bold text-amber-800 dark:bg-amber-500/15 dark:text-amber-300">ISOLATED USE ONLY</span>
                <span class="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white px-2.5 py-1 text-[11px] font-mono font-semibold text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">PHP <?= e(PHP_VERSION) ?> · <?= e(PHP_SAPI) ?></span>
              </div>
              <h2 class="mt-3 text-xl font-bold tracking-tight text-slate-900 dark:text-white sm:text-2xl">PHP2Shell Lab — Solution</h2>
              <p class="mt-1.5 max-w-3xl text-sm leading-relaxed text-slate-600 dark:text-slate-300">How to find, verify and demonstrate <span class="font-mono font-semibold text-rose-600 dark:text-rose-400">CVE-2026-109618</span> and <span class="font-mono font-semibold text-rose-600 dark:text-rose-400">CVE-2026-109619</span> inside this isolated container — and the <strong>Real-World Hunt</strong> tab teaches how to find them on real infrastructure. Both flaws live in the PHP engine (all web-serving SAPIs; <code class="font-mono">mod_php</code> is highest risk), not in this app code.</p>
              <p class="mt-2 text-xs text-slate-500 dark:text-slate-400">Built for <code class="rounded bg-slate-100 px-1 py-0.5 font-mono dark:bg-slate-800">php:8.4.26-fpm-alpine</code> (last 8.4 before patch). Fixed in 8.4.27 / 8.5.12 / 8.3.36 / 8.2.35. <span class="font-semibold">Never expose this container publicly.</span></p>
            </div>
            <div class="flex shrink-0 items-center gap-2">
              <button type="button" onclick="document.querySelector('[data-lab-tab=walkthrough]')?.click()" class="rounded-lg bg-emerald-600 px-4 py-2 text-xs font-bold text-white shadow-sm hover:bg-emerald-500">📖 Beginner Walkthrough</button>
              <button type="button" onclick="document.querySelector('[data-lab-tab=field]')?.click()" class="rounded-lg border border-indigo-300 bg-white px-4 py-2 text-xs font-bold text-indigo-700 shadow-sm hover:bg-indigo-50 dark:border-indigo-500/40 dark:bg-slate-800 dark:text-indigo-300">Real-world guide</button>
              <a href="#" data-view="runtime" class="rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">Check runtime</a>
            </div>
          </div>
          <div class="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div class="rounded-xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-700 dark:bg-slate-800/60">
              <p class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Your Engine Now</p>
              <p class="mt-1 font-mono text-sm font-bold text-slate-900 dark:text-white"><?= e(PHP_VERSION) ?> <span class="font-normal text-slate-500"><?= e(PHP_SAPI) ?></span></p>
              <p class="mt-1 text-xs text-emerald-600 dark:text-emerald-400">● Expected: 8.4.26 fpm-fcgi = vulnerable</p>
            </div>
            <div class="rounded-xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-700 dark:bg-slate-800/60">
              <p class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Uptime / Worker</p>
              <p class="mt-1 font-mono text-sm font-bold text-slate-900 dark:text-white"><?= e(container_uptime()) ?> <span class="font-normal text-slate-500">· pid <?= getmypid() ?></span></p>
              <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">Verify with <code class="font-mono">supervisorctl status</code></p>
            </div>
            <div class="rounded-xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-700 dark:bg-slate-800/60">
              <p class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Lab Health</p>
              <p class="mt-1 flex items-center gap-2 text-sm font-bold text-slate-900 dark:text-white"><span class="h-2 w-2 rounded-full bg-emerald-500"></span> nginx :80 → php-fpm :9000</p>
              <p class="mt-1 text-xs text-slate-500 dark:text-slate-400"><a class="font-mono text-indigo-600 dark:text-indigo-400 hover:underline" href="index.php?api=ping" target="_blank">/index.php?api=ping</a> should return <code>status:ok</code></p>
            </div>
          </div>
        </div>
      </div>

      <!-- error fix note -->
      <div class="rounded-xl border border-emerald-500/30 bg-emerald-50 px-4 py-3 text-sm leading-relaxed text-emerald-900 dark:border-emerald-500/25 dark:bg-emerald-500/10 dark:text-emerald-200">
        <span class="font-bold">✓ UI bug fixed in this build:</span> <code class="font-mono">container_uptime()</code> previously used float <code class="font-mono">%</code> which on PHP 8.4 emitted <em>“Implicit conversion from float 2437.52 to int loses precision”</em> on lines 54–55. Now it uses <code class="font-mono">fmod()</code> + <code class="font-mono">floor()</code>. If you still see those warnings, rebuild the image: <code class="rounded bg-white px-1 py-0.5 font-mono text-xs dark:bg-slate-800">docker build -t php2shell-lab:8.4.26 . && docker rm -f php2shell-vm && docker run -d --name php2shell-vm -p 127.0.0.1:8080:80 php2shell-lab:8.4.26</code>
      </div>

      <!-- tabs -->
      <div class="flex flex-wrap gap-2">
        <button type="button" data-lab-tab="overview" class="lab-tab rounded-full bg-indigo-600 px-4 py-1.5 text-xs font-bold text-white shadow-sm">Overview</button>
        <button type="button" data-lab-tab="walkthrough" class="lab-tab rounded-full border border-emerald-300 bg-emerald-50 px-4 py-1.5 text-xs font-bold text-emerald-700 hover:bg-emerald-100 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300">📖 Walkthrough <span class="ml-1 rounded-full bg-emerald-600 px-1.5 py-0.5 text-[10px] text-white">BEGINNER</span></button>
        <button type="button" data-lab-tab="cve618" class="lab-tab rounded-full border border-slate-200 bg-white px-4 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">CVE-2026-109618</button>
        <button type="button" data-lab-tab="cve619" class="lab-tab rounded-full border border-slate-200 bg-white px-4 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">CVE-2026-109619</button>
        <button type="button" data-lab-tab="verify" class="lab-tab rounded-full border border-slate-200 bg-white px-4 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">Verify &amp; Patch Test</button>
        <button type="button" data-lab-tab="field" class="lab-tab rounded-full border border-indigo-300 bg-indigo-50 px-4 py-1.5 text-xs font-bold text-indigo-700 hover:bg-indigo-100 dark:border-indigo-500/40 dark:bg-indigo-500/10 dark:text-indigo-300">Real-World Hunt · Tester Guide</button>
      </div>

      <!-- ══ Overview panel ══ -->
      <div data-lab-panel="overview" class="space-y-4">
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-bold text-slate-900 dark:text-white">Architecture You Are Attacking</h3>
          <p class="mt-1 text-xs leading-relaxed text-slate-500 dark:text-slate-400">Single container “VM”: <code class="font-mono font-semibold">supervisord (PID 1) → nginx :80 → php-fpm 127.0.0.1:9000</code>. The app (this page) is just a realistic dashboard; the bug is in <strong>php-src</strong> itself. That’s why even <code class="font-mono">?api=ping</code> proves you hit the FPM engine.</p>
          <div class="mt-4 overflow-x-auto rounded-xl border border-slate-200 bg-slate-950 p-4 font-mono text-xs leading-relaxed text-slate-200 dark:border-slate-700">
<pre>host 127.0.0.1:8080 ──► nginx :80 (supervised)
  ├── /healthz            nginx only  →  200 ok
  ├── *.php  ──FastCGI──► php-fpm 127.0.0.1:9000  (pool www)
  │                         └─ PHP 8.4.26  CVE-2026-109618 + CVE-2026-109619
  └── /        try_files → /index.php
supervisord = PID 1   docker logs -f php2shell-vm</pre>
          </div>
          <div class="mt-4 grid gap-3 sm:grid-cols-2">
            <div class="rounded-xl bg-indigo-50 p-3 dark:bg-indigo-500/10">
              <p class="text-xs font-bold text-indigo-900 dark:text-indigo-200">CVE-2026-109618 — OOM longjmp</p>
              <p class="mt-1 text-xs leading-relaxed text-indigo-800/80 dark:text-indigo-200/80">Engine runs out of memory while allocating a request, does <code class="font-mono">longjmp</code> to bail out, but leaves request memory uninitialized. Next allocation can see corrupted / previous content → RCE. Pre-auth, all web SAPIs (<code class="font-mono">mod_php</code> highest risk; no complete FPM exploit demonstrated for this CVE). CVSS 9.2. Fixed 8.4.27.</p>
            </div>
            <div class="rounded-xl bg-rose-50 p-3 dark:bg-rose-500/10">
              <p class="text-xs font-bold text-rose-900 dark:text-rose-200">CVE-2026-109619 — Stale global state</p>
              <p class="mt-1 text-xs leading-relaxed text-rose-800/80 dark:text-rose-200/80">Freed request memory is not cleared from a global; next request on the <em>same worker</em> reuses that pointer → use-after-free / info leak / RCE. Pre-auth, all web SAPIs; the FPM path was validated via the session lifecycle. CVSS 9.2. Fixed 8.4.27.</p>
            </div>
          </div>
        </div>

        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-bold text-slate-900 dark:text-white">Step-by-step — Solve the Lab</h3>
          <ol class="mt-3 space-y-3 text-sm leading-relaxed text-slate-700 dark:text-slate-300">
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-xs font-bold text-white">1</span><span><strong>Build &amp; run isolated:</strong> <code class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs dark:bg-slate-800">cd php2shell-lab && docker build -t php2shell-lab:8.4.26 . && docker run -d --name php2shell-vm -p 127.0.0.1:8080:80 --memory=512m --cpus=1 php2shell-lab:8.4.26</code>. Publish only on <code class="font-mono">127.0.0.1</code>. Never expose to your LAN.</span></li>
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-xs font-bold text-white">2</span><span><strong>Confirm you are on the vulnerable engine:</strong> <code class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs dark:bg-slate-800">curl -s http://127.0.0.1:8080/index.php?api=ping | jq</code> → <code class="font-mono">php: 8.4.26 + sapi: fpm-fcgi</code>. Also check the green “System Health” badge and the “Runtime Environment” view → PHP version / Zend / memory_limit = 256M in this image.</span></li>
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-xs font-bold text-white">3</span><span><strong>Do a safe baseline (no payload):</strong> <code class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs dark:bg-slate-800">python3 cve-demonstrations/collect_runtime.py --port 8080 &gt; baseline.json</code> (included in this repo). It does one ordinary GET, checks <code class="font-mono">sapi==fpm-fcgi</code>, and refuses non-loopback hosts.</span></li>
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-rose-600 text-xs font-bold text-white">4</span><span><strong>Test CVE-2026-109618:</strong> see next tab. The gist: trigger an allocation that hits <code class="font-mono">memory_limit</code> inside the engine; watch for the OOM → uninitialized memory path. A normal <code>Allowed memory size exhausted</code> message is <em>expected</em> — only a sanitizer/ASAN trace of uninitialized use proves the defect.</span></li>
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-rose-600 text-xs font-bold text-white">5</span><span><strong>Test CVE-2026-109619:</strong> see its tab. The gist: pin one FPM worker (<code class="font-mono">pm=static, max_children=1, max_requests=0</code>), send request A that leaves a freed object in a global, then request B on the <em>same PID</em> that dereferences it. You must instrument the pool to log PIDs.</span></li>
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-emerald-600 text-xs font-bold text-white">6</span><span><strong>Compare patched:</strong> rebuild with <code class="font-mono">--build-arg PHP_IMAGE=php:8.4.27-fpm-alpine</code> (or 8.5.12 / 8.3.36 / 8.2.35) and repeat identical steps. Vulnerability should disappear; keep image digests and <code class="font-mono">docker inspect</code> with your evidence. <strong>A crash or 500 alone is not RCE.</strong></span></li>
          </ol>
          <div class="mt-4 rounded-xl border border-amber-400/40 bg-amber-50 px-4 py-3 text-xs leading-relaxed text-amber-900 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-200"><strong>Rule:</strong> until you have a vendor advisory + fixing commit + sanitizer/debugger trace tied to the exact source revision, report <code class="font-mono">not reproduced / insufficient evidence</code>. Version strings alone cannot prove either bug (backported patches count). <button type="button" onclick="document.querySelector('[data-lab-tab=field]')?.click()" class="font-bold underline">Open the Real-World Hunt tab</button> for the 10-step tester workflow: inventory → fingerprint → backport check → attack requirements → evidence → report.</div>
        </div>
      </div>

<div data-lab-panel="walkthrough" class="hidden space-y-6">
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Space+Grotesk:wght@600;700&family=Press+Start+2P&display=swap');
.game-font{font-family:'Space Grotesk',system-ui,sans-serif}
.mono{font-family:'JetBrains Mono',monospace}
.pixel{font-family:'Press Start 2P',monospace}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
@keyframes pulse-glow{0%,100%{box-shadow:0 0 20px rgba(99,102,241,0.4),0 0 40px rgba(99,102,241,0.15)}50%{box-shadow:0 0 30px rgba(99,102,241,0.7),0 0 60px rgba(236,72,153,0.3)}}
@keyframes boss-pulse{0%,100%{transform:scale(1);filter:brightness(1)}50%{transform:scale(1.03);filter:brightness(1.15)}}
@keyframes glitch{0%,90%,100%{transform:translate(0)}92%{transform:translate(-1px,1px)}94%{transform:translate(1px,-1px)}}
@keyframes typing{from{width:0}to{width:100%}}
@keyframes shimmer{0%{background-position:-400px 0}100%{background-position:400px 0}}
@keyframes shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-4px)}40%,80%{transform:translateX(4px)}}
@keyframes confetti{0%{transform:translateY(-10px) rotate(0) scale(1);opacity:1}100%{transform:translateY(400px) rotate(720deg) scale(0.8);opacity:0}}
@keyframes grid-move{0%{transform:translateY(0)}100%{transform:translateY(20px)}}
@keyframes scan{0%{transform:translateY(-100%)}100%{transform:translateY(100%)}}
.float{animation:float 3s ease-in-out infinite}
.pulse-glow{animation:pulse-glow 2s ease-in-out infinite}
.boss-pulse{animation:boss-pulse 1.6s ease-in-out infinite}
.glitch{animation:glitch 4s infinite}
.shake{animation:shake 0.35s}
.scan-line::after{content:'';position:absolute;inset:0;background:linear-gradient(transparent,rgba(16,185,129,0.35),transparent);height:40%;animation:scan 2s linear infinite;pointer-events:none}
.game-card{transition:all 0.3s cubic-bezier(0.34,1.56,0.64,1)}
.game-card:hover{transform:translateY(-4px) scale(1.02)}
.game-card:active{transform:scale(0.98)}
.mission-locked{filter:grayscale(0.85) opacity(0.6)}
.mission-done{border-color:rgb(16 185 129)!important;background:linear-gradient(135deg,#ecfdf5,white)}
.dark .mission-done{background:linear-gradient(135deg,rgba(16,185,129,0.15),rgba(15,23,42,1))}
.xp-orb{background:radial-gradient(circle at 30% 30%,#fde68a,#f59e0b,#b45309);box-shadow:inset 0 2px 4px rgba(255,255,255,0.6),0 2px 8px rgba(245,158,11,0.5)}
.badge-pop{animation:float 0.6s cubic-bezier(0.34,1.56,0.64,1)}
.terminal-cursor::after{content:'█';animation:blink 1s step-end infinite;margin-left:2px;color:#10b981}
@keyframes blink{0%,50%{opacity:1}51%,100%{opacity:0}}
.grid-bg{background-image:linear-gradient(rgba(99,102,241,0.07) 1px,transparent 1px),linear-gradient(90deg,rgba(99,102,241,0.07) 1px,transparent 1px);background-size:24px 24px}
.matrix{position:absolute;inset:0;overflow:hidden;opacity:0.06;pointer-events:none;font-family:'JetBrains Mono',monospace;font-size:10px;line-height:10px;word-break:break-all;user-select:none}
</style>

<!-- ═══════════════════ HERO: OPERATION MIDNIGHT PATCH ═══════════════════ -->
<div class="relative overflow-hidden rounded-[24px] border border-slate-900 bg-slate-950 shadow-2xl">
  <div class="absolute inset-0 grid-bg"></div>
  <div class="matrix" id="matrix-rain">01010111 01100101 00100000 01100001 01110010 01100101 00100000 01101000 01100001 01100011 01101011 01100101 01100100 00100000 — CVE-2026-109618 — CVE-2026-109619 — RCE — OOM — UAF — 01010111 01100101 — NIMBUS — PHP 8.4.26 — FPM — nginx — memory_limit — upload_progress — max_requests — 0101 — GHSA-w8hw-w9fx-j79w — GHSA-6wmf-4rv5-p3rp —</div>
  <div class="absolute inset-0 bg-gradient-to-br from-indigo-600/20 via-transparent to-emerald-600/20"></div>
  <!-- top bar -->
  <div class="relative flex flex-wrap items-center justify-between gap-3 border-b border-white/10 bg-black/40 px-5 py-3 backdrop-blur">
    <div class="flex items-center gap-2">
      <span class="h-2.5 w-2.5 animate-pulse rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]"></span>
      <span class="pixel text-[9px] tracking-[0.18em] text-emerald-400">SYSTEM ONLINE</span>
      <span class="mono ml-2 hidden text-[11px] text-white/50 sm:inline">nimbus.internal:8080 · php-fpm:9000 · nginx:80</span>
    </div>
    <div class="flex items-center gap-2">
      <span class="rounded-full bg-white/10 px-2.5 py-1 text-[10px] font-bold text-white">12 MISSIONS</span>
      <span class="rounded-full bg-rose-500 px-2.5 py-1 text-[10px] font-bold text-white">2 BOSS CVEs</span>
      <span class="rounded-full bg-amber-400 px-2.5 py-1 text-[10px] font-bold text-amber-900">★ 2400 XP</span>
    </div>
  </div>
  <div class="relative grid gap-6 px-6 py-8 lg:grid-cols-[1.35fr_0.85fr] lg:px-8 lg:py-9">
    <div>
      <div class="inline-flex items-center gap-2 rounded-full bg-gradient-to-r from-amber-400 to-orange-500 px-3 py-1 text-[11px] font-bold text-amber-950 shadow-lg">
        <span>🔥</span> NEW · INTERACTIVE HACK THE BOX EDITION
      </div>
      <h2 class="game-font mt-3 text-[26px] font-bold leading-[0.95] tracking-tight text-white sm:text-[32px]">
        <span class="bg-gradient-to-r from-indigo-400 via-fuchsia-400 to-emerald-400 bg-clip-text text-transparent">OPERATION</span><br/>
        <span class="glitch inline-block text-white">MIDNIGHT PATCH</span>
        <span class="ml-2 align-super rounded-full bg-rose-600 px-2 py-0.5 text-[11px] font-bold tracking-widest text-white">2 CVEs</span>
      </h2>
      <p class="mono mt-3 max-w-xl text-[12px] leading-relaxed text-white/70">
        <span class="font-bold text-emerald-400">03:17 AM — NIMBUS HQ.</span> Senior Engineer Sage pinged you: <em class="text-white">“Two zero-days in our PHP engine. One crashes memory, one haunts workers. Find them before the internet does. You in, rookie?”</em><br/>
        No experience? No problem. This is a <span class="rounded bg-white/10 px-1 py-0.5 font-bold text-white">story-driven, hands-on game</span> — each mission is a puzzle, each CVE a boss fight. You’ll run real commands against a real vulnerable container and collect evidence pros use.
      </p>
      <div class="mt-5 flex flex-wrap gap-2">
        <button type="button" onclick="document.getElementById('mission-board')?.scrollIntoView({behavior:'smooth'})" class="inline-flex items-center gap-2 rounded-full bg-white px-5 py-2.5 text-xs font-bold text-slate-900 shadow-lg hover:bg-slate-100">▶ PLAY MISSION 1 <span class="rounded-full bg-emerald-500 px-2 py-0.5 text-[10px] text-white">FREE</span></button>
        <button type="button" onclick="document.getElementById('how-to-play')?.scrollIntoView({behavior:'smooth'})" class="rounded-full border border-white/20 bg-white/10 px-5 py-2.5 text-xs font-bold text-white backdrop-blur hover:bg-white/15">How to play?</button>
        <a href="?walkthrough=raw" target="_blank" class="mono rounded-full border border-white/10 px-4 py-2.5 text-[11px] text-white/60 hover:text-white">📄 raw .md</a>
      </div>
      <div class="mt-5 flex flex-wrap gap-2 text-[11px]">
        <span class="inline-flex items-center gap-1.5 rounded-full bg-white/10 px-3 py-1.5 text-white/80 backdrop-blur"><span class="h-2 w-2 rounded-full bg-emerald-400"></span> Live container check: <span id="game-live-dot" class="font-mono font-bold text-white">checking…</span></span>
        <span class="inline-flex items-center gap-1.5 rounded-full bg-indigo-500/20 px-3 py-1.5 font-bold text-indigo-200">⌛ 90–120 min · No exploit needed · L2 wins</span>
      </div>
    </div>
    <!-- right: boss preview + quick stats -->
    <div class="space-y-3">
      <div class="grid grid-cols-2 gap-3">
        <div class="relative overflow-hidden rounded-2xl border border-indigo-400/50 bg-gradient-to-br from-indigo-600 to-violet-700 p-4 text-white shadow-xl">
          <div class="absolute -right-6 -top-6 text-5xl opacity-20">🧠</div>
          <p class="mono text-[10px] tracking-[0.16em] text-indigo-200">BOSS · CVE-2026-109618</p>
          <p class="mt-1 text-sm font-bold leading-tight">MEMORY<br/>LEVIATHAN</p>
          <p class="mono mt-1 text-[11px] leading-relaxed text-indigo-100/80">OOM → dirty memory → RCE. <code class="rounded bg-black/20 px-1">memory_limit 256M</code></p>
          <div class="mt-3 h-1.5 overflow-hidden rounded-full bg-black/20"><div class="h-full w-[72%] rounded-full bg-white"></div></div>
          <p class="mono mt-1 text-[10px] text-white/60">Difficulty ★★★★</p>
        </div>
        <div class="relative overflow-hidden rounded-2xl border border-rose-400/50 bg-gradient-to-br from-rose-600 to-orange-600 p-4 text-white shadow-xl">
          <div class="absolute -right-6 -top-6 text-5xl opacity-20">👻</div>
          <p class="mono text-[10px] tracking-[0.16em] text-rose-100">BOSS · CVE-2026-109619</p>
          <p class="mt-1 text-sm font-bold leading-tight">GHOST<br/>WORKER</p>
          <p class="mono mt-1 text-[11px] leading-relaxed text-rose-100/80">Freed pointer → same PID → RCE. <code class="rounded bg-black/20 px-1">upload_progress On</code></p>
          <div class="mt-3 h-1.5 overflow-hidden rounded-full bg-black/20"><div class="h-full w-[68%] rounded-full bg-white"></div></div>
          <p class="mono mt-1 text-[10px] text-white/60">Difficulty ★★★★</p>
        </div>
      </div>
      <div class="rounded-2xl border border-white/10 bg-white/[0.06] p-4 backdrop-blur">
        <p class="mono text-[11px] font-bold tracking-wide text-white">🎮 How you win (no hacking exp needed)</p>
        <ul class="mono mt-2 space-y-1.5 text-[11px] leading-relaxed text-white/70">
          <li>✅ <span class="font-bold text-white">Play 12 missions in order</span> — each is 5–10 min, copy-paste commands</li>
          <li>✅ <span class="font-bold text-white">Beat 2 bosses</span> — prove version+config+evidence (L2) — no exploit</li>
          <li>✅ <span class="font-bold text-white">Collect 12 badges</span> — level up from Script Kiddie → Legend</li>
        </ul>
        <p class="mono mt-3 rounded-lg bg-emerald-500/15 px-3 py-2 text-[11px] font-bold text-emerald-300">💡 Pro tip: “A crash is not a hack.” You’ll learn the difference in Mission 8 and flex on seniors.</p>
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════════ STICKY XP BAR ═══════════════════ -->
<div id="game-xp-bar" class="sticky top-0 z-[8] -mx-1 overflow-hidden rounded-2xl border border-slate-200 bg-white/95 shadow-lg backdrop-blur dark:border-slate-800 dark:bg-slate-900/95">
  <div class="flex flex-wrap items-center gap-3 px-4 py-3">
    <div class="flex items-center gap-3">
      <div id="game-avatar" class="grid h-10 w-10 place-items-center rounded-full border-2 border-amber-300 bg-gradient-to-br from-amber-100 to-orange-100 text-lg">🐱</div>
      <div>
        <p class="game-font text-xs font-bold leading-none text-slate-900 dark:text-white"><span id="game-level-name">Script Kiddie</span> <span class="ml-1 rounded-full bg-indigo-600 px-1.5 py-0.5 text-[10px] font-bold text-white">LV <span id="game-level">1</span></span></p>
        <p class="mono text-[11px] text-slate-500"><span id="game-xp">0</span> XP · <span id="game-progress-text">0/12 missions</span> · <span id="game-pct">0%</span></p>
      </div>
    </div>
    <div class="min-w-[140px] flex-1">
      <div class="h-2.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
        <div id="game-xp-fill" class="h-full rounded-full bg-gradient-to-r from-amber-400 via-orange-500 to-rose-500 transition-all duration-700" style="width:0%"></div>
      </div>
      <div class="mono mt-1 flex justify-between text-[10px] text-slate-400">
        <span id="game-next-lvl">Next: Packet Peeker (150 XP)</span>
        <span id="game-streak">🔥 0 streak</span>
      </div>
    </div>
    <div class="flex items-center gap-2">
      <div id="evidence-mini" class="hidden items-center gap-1 sm:flex">
        <span class="mono text-[10px] font-bold text-slate-500">EVIDENCE</span>
        <span class="grid h-7 w-7 place-items-center rounded-lg border border-slate-200 bg-slate-50 text-[11px] dark:border-slate-700 dark:bg-slate-800" title="Headers">📡</span>
        <span class="grid h-7 w-7 place-items-center rounded-lg border border-slate-200 bg-slate-50 text-[11px] dark:border-slate-700 dark:bg-slate-800" title="Version">🏷️</span>
        <span class="grid h-7 w-7 place-items-center rounded-lg border border-slate-200 bg-slate-50 text-[11px] dark:border-slate-700 dark:bg-slate-800" title="Patch">🩹</span>
        <span class="grid h-7 w-7 place-items-center rounded-lg border border-slate-200 bg-slate-50 text-[11px] dark:border-slate-700 dark:bg-slate-800" title="Config">⚙️</span>
        <span class="grid h-7 w-7 place-items-center rounded-lg border border-slate-200 bg-slate-50 text-[11px] dark:border-slate-700 dark:bg-slate-800" title="PID">👻</span>
        <span class="grid h-7 w-7 place-items-center rounded-lg border border-slate-200 bg-slate-50 text-[11px] dark:border-slate-700 dark:bg-slate-800" title="Report">📝</span>
      </div>
      <button type="button" onclick="gameReset()" class="mono rounded-full border border-slate-200 px-3 py-1.5 text-[11px] font-bold text-slate-500 hover:bg-slate-50 dark:border-slate-700">Reset</button>
    </div>
  </div>
</div>

<!-- ═══════════════════ CHOOSE YOUR FIGHTER ═══════════════════ -->
<div id="how-to-play" class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
  <div class="flex flex-wrap items-center gap-2">
    <h3 class="game-font text-sm font-bold text-slate-900 dark:text-white">🎭 Choose your fighter</h3>
    <span class="mono rounded-full bg-amber-100 px-2 py-0.5 text-[11px] font-bold text-amber-800 dark:bg-amber-500/15 dark:text-amber-300">pick one — affects nothing, vibes only</span>
    <span class="mono ml-auto text-[11px] text-slate-400">Tip: you can change anytime</span>
  </div>
  <div class="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
    <button type="button" data-avatar="🐱" class="avatar-btn group rounded-2xl border-2 border-amber-400 bg-amber-50 p-4 text-left shadow-sm dark:bg-amber-500/10">
      <div class="text-2xl">🐱</div><p class="mt-1 text-xs font-bold text-slate-900 dark:text-white">Hacker Cat</p><p class="mono text-[11px] text-slate-500">“meow or never” — 9 lives, 0 fear</p><p class="mono mt-1 text-[10px] font-bold text-emerald-600">✓ SELECTED</p>
    </button>
    <button type="button" data-avatar="🕶️" class="avatar-btn group rounded-2xl border border-slate-200 bg-white p-4 text-left hover:border-slate-300 dark:border-slate-700 dark:bg-slate-800">
      <div class="text-2xl">🕶️</div><p class="mt-1 text-xs font-bold text-slate-900 dark:text-white">Mr. Hoodie</p><p class="mono text-[11px] text-slate-500">“I read the manual” — actually didn’t</p><p class="mono mt-1 text-[10px] text-slate-400">click to equip</p>
    </button>
    <button type="button" data-avatar="🤖" class="avatar-btn group rounded-2xl border border-slate-200 bg-white p-4 text-left hover:border-slate-300 dark:border-slate-700 dark:bg-slate-800">
      <div class="text-2xl">🤖</div><p class="mt-1 text-xs font-bold text-slate-900 dark:text-white">Sage-Bot</p><p class="mono text-[11px] text-slate-500">“beep boop, patch your PHP”</p><p class="mono mt-1 text-[10px] text-slate-400">click to equip</p>
    </button>
    <button type="button" data-avatar="👾" class="avatar-btn group rounded-2xl border border-slate-200 bg-white p-4 text-left hover:border-slate-300 dark:border-slate-700 dark:bg-slate-800">
      <div class="text-2xl">👾</div><p class="mt-1 text-xs font-bold text-slate-900 dark:text-white">Glitch</p><p class="mono text-[11px] text-slate-500">“I live in the worker” — spooky</p><p class="mono mt-1 text-[10px] text-slate-400">click to equip</p>
    </button>
  </div>
  <div class="mt-4 flex gap-3 rounded-xl border border-indigo-200 bg-indigo-50 p-3 dark:border-indigo-500/20 dark:bg-indigo-500/10">
    <div class="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-indigo-600 text-sm text-white">🧙</div>
    <div>
      <p class="text-xs font-bold text-indigo-900 dark:text-indigo-200">Sage (your mentor) says:</p>
      <p class="mono mt-1 text-xs leading-relaxed text-indigo-900/80 dark:text-indigo-200/80">“Listen, rookie — you don’t need to be a wizard. Run the commands, read the clues, collect the receipts. By Mission 8 you’ll know more than half the ‘seniors’ on Twitter. And if you get stuck? Smash the <span class="rounded bg-white px-1 py-0.5 font-bold dark:bg-slate-800">💡 HINT</span> button. No shame.”</p>
    </div>
  </div>
</div>

<!-- ═══════════════════ MISSION BOARD ═══════════════════ -->
<div id="mission-board" class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
  <div class="flex flex-wrap items-center gap-3">
    <h3 class="game-font text-sm font-bold text-slate-900 dark:text-white">🗺️ THE HUNT BOARD — 12 missions, 2 bosses</h3>
    <span class="mono rounded-full bg-slate-900 px-2.5 py-1 text-[11px] font-bold text-white dark:bg-white dark:text-slate-900">Click a card to play</span>
    <div class="ml-auto flex items-center gap-2">
      <span class="mono text-[11px] text-slate-400">Speedrun</span>
      <button type="button" id="speedrun-toggle" class="rounded-full border border-slate-200 bg-white px-3 py-1 text-[11px] font-bold text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">⏱ OFF</button>
      <span id="speedrun-time" class="mono hidden text-[11px] font-bold text-indigo-600">00:00</span>
    </div>
  </div>
  <p class="mono mt-1 text-[11px] leading-relaxed text-slate-500">Complete in order to unlock boss fights. <span class="font-bold text-emerald-600">Green = done, pulsing = ready, locked = do previous first.</span> Each mission ≈ 5–10 min. Bosses need extra proof.</p>

  <!-- path + grid -->
  <div class="relative mt-5">
    <div class="absolute left-[18px] top-6 bottom-6 w-0.5 bg-gradient-to-b from-emerald-400 via-indigo-400 to-slate-200 dark:to-slate-700 sm:left-1/2 sm:-translate-x-[1px]"></div>
    <div id="game-path-fill" class="absolute left-[18px] top-6 w-0.5 bg-gradient-to-b from-emerald-500 to-indigo-600 transition-all duration-700 sm:left-1/2 sm:-translate-x-[1px]" style="height:0%"></div>
    <div id="mission-grid" class="relative space-y-3"></div>
  </div>

  <div class="mt-4 flex flex-wrap gap-2">
    <button type="button" onclick="gameHintBoard()" class="rounded-full bg-amber-400 px-4 py-2 text-xs font-bold text-amber-900 hover:bg-amber-300">💡 Stuck? Get a hint</button>
    <button type="button" onclick="document.getElementById('boss-arena')?.scrollIntoView({behavior:'smooth'})" class="rounded-full border border-slate-200 bg-white px-4 py-2 text-xs font-semibold text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">👁 Meet the bosses</button>
    <span class="mono ml-auto hidden items-center gap-1 text-[11px] text-slate-400 sm:flex">🎮 Pro move: press <code class="rounded bg-slate-100 px-1.5 py-0.5 dark:bg-slate-800">1</code>–<code class="rounded bg-slate-100 px-1.5 py-0.5 dark:bg-slate-800">9</code> to jump to missions</span>
  </div>
</div>

<!-- ═══════════════════ MISSION DRAWER ═══════════════════ -->
<div id="mission-drawer" class="hidden overflow-hidden rounded-2xl border-2 border-indigo-300 bg-white shadow-xl dark:border-indigo-500/40 dark:bg-slate-900">
  <div class="border-b border-slate-200 bg-gradient-to-r from-indigo-50 via-white to-emerald-50 px-5 py-4 dark:border-slate-800 dark:from-indigo-500/10 dark:via-slate-900 dark:to-emerald-500/10">
    <div class="flex items-start justify-between gap-3">
      <div class="flex gap-3">
        <div id="drawer-icon" class="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-slate-900 text-lg text-white">1</div>
        <div>
          <p class="mono text-[10px] font-bold tracking-[0.14em] text-slate-500"><span id="drawer-num">MISSION 01</span> · <span id="drawer-xp">100 XP</span> · <span id="drawer-diff">★★☆</span></p>
          <h3 id="drawer-title" class="game-font text-base font-bold text-slate-900 dark:text-white">Wake Up, Neo</h3>
          <p id="drawer-subtitle" class="mono text-xs text-slate-500">Is anyone home?</p>
        </div>
      </div>
      <button type="button" onclick="closeMission()" class="grid h-8 w-8 place-items-center rounded-full border border-slate-200 bg-white text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800">✕</button>
    </div>
    <div class="mt-3 flex gap-1.5">
      <button type="button" data-drawer-tab="brief" class="drawer-tab rounded-full bg-slate-900 px-3 py-1.5 text-xs font-bold text-white">📋 Briefing</button>
      <button type="button" data-drawer-tab="hack" class="drawer-tab rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">💻 Hack Lab</button>
      <button type="button" data-drawer-tab="quiz" class="drawer-tab rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">🧠 Quiz & Loot</button>
    </div>
  </div>

  <!-- briefing tab -->
  <div data-drawer-panel="brief" class="p-5">
    <div class="flex gap-3">
      <div class="hidden h-8 w-8 shrink-0 place-items-center rounded-full bg-indigo-600 text-sm text-white sm:grid">🧙</div>
      <div class="flex-1 rounded-2xl border border-indigo-200 bg-indigo-50 px-4 py-3 dark:border-indigo-500/20 dark:bg-indigo-500/10">
        <p class="text-xs font-bold text-indigo-900 dark:text-indigo-200">Sage whispers:</p>
        <p id="drawer-sage" class="mono mt-1 text-xs leading-relaxed text-indigo-900/80 dark:text-indigo-200/80">—</p>
      </div>
    </div>
    <div id="drawer-brief" class="prose prose-sm mt-4 max-w-none text-sm leading-relaxed text-slate-600 dark:text-slate-300"></div>
    <div class="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3 dark:border-slate-700 dark:bg-slate-800/50">
      <p class="mono text-[11px] font-bold text-slate-700 dark:text-slate-200">🎯 Objective — do this to finish the mission:</p>
      <ul id="drawer-objective" class="mono mt-2 list-disc space-y-1 pl-5 text-xs leading-relaxed text-slate-600 dark:text-slate-400"></ul>
    </div>
  </div>

  <!-- hack tab -->
  <div data-drawer-panel="hack" class="hidden p-5">
    <p class="mono text-xs font-bold text-slate-900 dark:text-white">💻 Hack Lab — run real commands against the live container. Nothing breaks; it’s your playground.</p>
    <div class="mt-3 flex flex-wrap gap-2" id="drawer-commands"></div>
    <div class="relative mt-3 overflow-hidden rounded-xl border border-slate-900 bg-slate-950">
      <div class="flex items-center justify-between border-b border-white/10 bg-black/50 px-3 py-2">
        <span class="mono text-[11px] font-bold tracking-wide text-emerald-400">● TERMINAL — nimbus@lab:~$</span>
        <div class="flex gap-1.5"><span class="h-2.5 w-2.5 rounded-full bg-rose-500"></span><span class="h-2.5 w-2.5 rounded-full bg-amber-400"></span><span class="h-2.5 w-2.5 rounded-full bg-emerald-500"></span></div>
      </div>
      <div id="drawer-terminal" class="mono max-h-[260px] min-h-[120px] overflow-y-auto whitespace-pre-wrap break-words px-4 py-3 text-xs leading-relaxed text-emerald-300">Click a command above to run it. Your output appears here like a real terminal. ↓</div>
      <div class="flex gap-2 border-t border-white/10 bg-black/30 px-3 py-2">
        <input id="drawer-input" placeholder="or type a command and press Enter…" class="mono flex-1 rounded-full bg-white/10 px-3 py-1.5 text-xs text-white placeholder:text-white/40 outline-none"/>
        <button type="button" onclick="runCustomCommand()" class="mono rounded-full bg-emerald-600 px-4 py-1.5 text-xs font-bold text-white hover:bg-emerald-500">Run</button>
      </div>
    </div>
    <p class="mono mt-2 text-[11px] text-slate-400">💡 Tip: every command shows <span class="font-bold text-emerald-600">what to look for</span>. If you see it, you’re done — claim loot!</p>
  </div>

  <!-- quiz tab -->
  <div data-drawer-panel="quiz" class="hidden p-5">
    <div id="drawer-quiz"></div>
    <div id="drawer-loot" class="mt-4 rounded-xl border-2 border-amber-300 bg-gradient-to-br from-amber-50 to-orange-50 p-4 dark:border-amber-500/30 dark:from-amber-500/10 dark:to-orange-500/10">
      <div class="flex items-center gap-3">
        <div id="drawer-badge" class="grid h-12 w-12 place-items-center rounded-xl bg-white text-xl shadow-sm dark:bg-slate-800">🏆</div>
        <div class="flex-1">
          <p class="text-xs font-bold text-slate-900 dark:text-white">Loot: <span id="drawer-badge-name">First Blood</span> <span id="drawer-badge-xp" class="ml-1 rounded-full bg-amber-400 px-2 py-0.5 text-[10px] font-bold text-amber-900">+100 XP</span></p>
          <p id="drawer-badge-desc" class="mono text-[11px] text-slate-600 dark:text-slate-400">Complete the quiz + run one command to unlock.</p>
        </div>
      </div>
      <button type="button" id="drawer-claim" onclick="claimMission()" class="mt-3 w-full rounded-full bg-gradient-to-r from-amber-400 to-orange-500 px-4 py-2.5 text-sm font-bold text-amber-950 shadow-md hover:from-amber-300 hover:to-orange-400 disabled:opacity-40">🔒 Answer quiz & run a command to unlock</button>
      <p class="mono mt-2 text-center text-[11px] text-slate-400">No gatekeeping — wrong answers just give funnier hints. You keep trying until you get it.</p>
    </div>
  </div>
</div>

<!-- ═══════════════════ BOSS ARENA ═══════════════════ -->
<div id="boss-arena" class="grid gap-4 lg:grid-cols-2">
  <div class="group relative overflow-hidden rounded-2xl border-2 border-indigo-300 bg-gradient-to-br from-indigo-600 via-violet-600 to-indigo-700 p-5 text-white shadow-xl dark:border-indigo-500/30">
    <div class="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(255,255,255,0.18),transparent_50%)]"></div>
    <div class="absolute -right-10 -top-10 text-[110px] opacity-[0.14] group-hover:opacity-[0.2] transition-opacity">🧠</div>
    <div class="relative">
      <div class="flex items-center gap-2">
        <span class="rounded-full bg-white px-2.5 py-1 text-[11px] font-bold text-indigo-700">BOSS 1</span>
        <span class="rounded-full bg-black/20 px-2.5 py-1 text-[11px] font-bold text-white">CVE-2026-109618 · CVSS 9.2</span>
        <span class="ml-auto hidden rounded-full bg-amber-400 px-2.5 py-1 text-[11px] font-bold text-amber-900 sm:inline">MISSION 8</span>
      </div>
      <h3 class="game-font mt-3 text-xl font-bold leading-none">MEMORY LEVIATHAN</h3>
      <p class="mono text-[11px] tracking-[0.12em] text-indigo-100">RCE VIA OOM CORRUPTION · FPM SAPI · PRE-AUTH</p>
      <div class="mt-3 h-2 overflow-hidden rounded-full bg-black/25">
        <div class="h-full w-[88%] rounded-full bg-gradient-to-r from-amber-300 to-white"></div>
      </div>
      <p class="mono mt-1 text-[10px] text-white/60">HP 88% · Weakness: sanitizer traces · Resists: “it just 500’d so it’s hacked”</p>
      <div class="mt-4 rounded-xl bg-black/20 p-3 backdrop-blur">
        <p class="text-xs font-bold">In plain English (no jargon):</p>
        <p class="mono mt-1 text-xs leading-relaxed text-indigo-50/90">PHP gets a huge upload, hits <code class="rounded bg-black/30 px-1 font-bold">memory_limit 256M</code>, panics and “teleports” out via <code class="rounded bg-black/30 px-1">longjmp</code> without cleaning up. The next thing it touches is <em>dirty memory</em> → an attacker can turn that into code execution. Your job isn’t to exploit it — it’s to <span class="font-bold text-amber-300">prove the conditions</span>: old version <span class="font-mono font-bold">8.4.26 < 8.4.27</span> + FPM + 256M + uploads allowed.</p>
      </div>
      <div class="mt-3 grid grid-cols-3 gap-2 text-center">
        <div class="rounded-xl bg-white/10 p-2 backdrop-blur"><p class="mono text-[10px] text-white/60">FIND IT IN</p><p class="text-xs font-bold">Task 4+5+8</p></div>
        <div class="rounded-xl bg-white/10 p-2 backdrop-blur"><p class="mono text-[10px] text-white/60">PROOF</p><p class="text-xs font-bold">L2 config + 500≠RCE demo</p></div>
        <div class="rounded-xl bg-white/10 p-2 backdrop-blur"><p class="mono text-[10px] text-white/60">FIX</p><p class="text-xs font-bold">8.4.27+</p></div>
      </div>
      <button type="button" onclick="openMission(8)" class="mt-4 w-full rounded-full bg-white px-4 py-2.5 text-xs font-bold text-indigo-700 shadow-lg hover:bg-indigo-50">⚔️ FIGHT THIS BOSS — OPEN MISSION 8</button>
      <button type="button" onclick="playMemoryGame()" class="mt-2 w-full rounded-full border border-white/30 bg-white/10 px-4 py-2 text-xs font-bold text-white backdrop-blur hover:bg-white/15">🎮 Play mini-game: Fill the memory bar</button>
      <div id="memory-game" class="mt-3 hidden rounded-xl bg-black/30 p-3">
        <p class="mono text-xs font-bold text-white">🧪 Mini-game: Hold to allocate memory…</p>
        <div class="mt-2 h-4 overflow-hidden rounded-full bg-black/50"><div id="memory-bar" class="h-full w-0 rounded-full bg-gradient-to-r from-emerald-400 to-amber-400 transition-all duration-150"></div></div>
        <p id="memory-msg" class="mono mt-2 text-xs text-white/80">Press and hold the button. What happens at 100%?</p>
        <button type="button" id="memory-hold" class="mt-2 w-full select-none rounded-full bg-amber-400 px-4 py-2 text-xs font-bold text-amber-900 active:scale-95">HOLD TO ALLOCATE</button>
      </div>
    </div>
  </div>

  <div class="group relative overflow-hidden rounded-2xl border-2 border-rose-300 bg-gradient-to-br from-rose-600 via-orange-600 to-rose-700 p-5 text-white shadow-xl dark:border-rose-500/30">
    <div class="absolute inset-0 bg-[radial-gradient(circle_at_70%_20%,rgba(255,255,255,0.16),transparent_50%)]"></div>
    <div class="absolute -right-10 -top-10 text-[110px] opacity-[0.14] group-hover:opacity-[0.2] transition-opacity">👻</div>
    <div class="relative">
      <div class="flex items-center gap-2">
        <span class="rounded-full bg-white px-2.5 py-1 text-[11px] font-bold text-rose-700">BOSS 2</span>
        <span class="rounded-full bg-black/20 px-2.5 py-1 text-[11px] font-bold text-white">CVE-2026-109619 · CVSS 9.2</span>
        <span class="ml-auto hidden rounded-full bg-amber-400 px-2.5 py-1 text-[11px] font-bold text-amber-900 sm:inline">MISSION 7</span>
      </div>
      <h3 class="game-font mt-3 text-xl font-bold leading-none">GHOST WORKER</h3>
      <p class="mono text-[11px] tracking-[0.12em] text-rose-100">RCE VIA STALE GLOBAL STATE · FPM SAPI · PRE-AUTH</p>
      <div class="mt-3 h-2 overflow-hidden rounded-full bg-black/25">
        <div class="h-full w-[82%] rounded-full bg-gradient-to-r from-amber-300 to-white"></div>
      </div>
      <p class="mono mt-1 text-[10px] text-white/60">HP 82% · Weakness: same-PID proof · Resists: recycled workers</p>
      <div class="mt-4 rounded-xl bg-black/20 p-3 backdrop-blur">
        <p class="text-xs font-bold">In plain English:</p>
        <p class="mono mt-1 text-xs leading-relaxed text-rose-50/90">PHP frees an object but <em>forgets to clear the pointer</em>. It sits there like a ghost. Next request that lands on the <span class="font-bold text-amber-200">same worker process</span> picks up the ghost and uses it → attacker controls it → RCE. You prove exposure by showing: <code class="rounded bg-black/30 px-1 font-bold">8.4.26</code> + FPM + <code class="rounded bg-black/30 px-1">upload_progress On</code> + <code class="rounded bg-black/30 px-1">pm.max_requests 0</code> (workers never die) + same PID.</p>
      </div>
      <div class="mt-3 grid grid-cols-3 gap-2 text-center">
        <div class="rounded-xl bg-white/10 p-2 backdrop-blur"><p class="mono text-[10px] text-white/60">FIND IT IN</p><p class="text-xs font-bold">Task 4+5+7</p></div>
        <div class="rounded-xl bg-white/10 p-2 backdrop-blur"><p class="mono text-[10px] text-white/60">PROOF</p><p class="text-xs font-bold">Same PID demo</p></div>
        <div class="rounded-xl bg-white/10 p-2 backdrop-blur"><p class="mono text-[10px] text-white/60">FIX</p><p class="text-xs font-bold">8.4.27+</p></div>
      </div>
      <button type="button" onclick="openMission(7)" class="mt-4 w-full rounded-full bg-white px-4 py-2.5 text-xs font-bold text-rose-700 shadow-lg hover:bg-rose-50">⚔️ FIGHT THIS BOSS — OPEN MISSION 7</button>
      <button type="button" onclick="playGhostGame()" class="mt-2 w-full rounded-full border border-white/30 bg-white/10 px-4 py-2 text-xs font-bold text-white backdrop-blur hover:bg-white/15">🎮 Play mini-game: Catch the ghost PID</button>
      <div id="ghost-game" class="mt-3 hidden rounded-xl bg-black/30 p-3">
        <p class="mono text-xs font-bold text-white">👻 Mini-game: Catch the repeating PID!</p>
        <div id="ghost-pids" class="mt-2 grid grid-cols-5 gap-2 text-center"></div>
        <p id="ghost-msg" class="mono mt-2 text-xs text-white/80">Click the PID that appears twice — that’s the ghost worker.</p>
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════════ EVIDENCE LOCKER ═══════════════════ -->
<div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
  <div class="flex flex-wrap items-center gap-2">
    <h3 class="game-font text-sm font-bold text-slate-900 dark:text-white">🧳 Evidence Locker — your loot</h3>
    <span class="mono rounded-full bg-slate-900 px-2.5 py-1 text-[11px] font-bold text-white dark:bg-white dark:text-slate-900"><span id="locker-count">0</span>/6 collected</span>
    <span class="mono text-[11px] text-slate-400">Fill this to reach L2 “likely exposed” — enough to force a patch!</span>
  </div>
  <div class="mt-4 grid grid-cols-3 gap-3 sm:grid-cols-6">
    <div data-locker="1" class="rounded-xl border-2 border-dashed border-slate-200 bg-slate-50 p-3 text-center opacity-60 dark:border-slate-700 dark:bg-slate-800/50"><div class="text-lg">📡</div><p class="mono text-[11px] font-bold text-slate-600 dark:text-slate-300">Headers</p><p class="mono text-[10px] text-slate-400">M2</p></div>
    <div data-locker="2" class="rounded-xl border-2 border-dashed border-slate-200 bg-slate-50 p-3 text-center opacity-60 dark:border-slate-700 dark:bg-slate-800/50"><div class="text-lg">🏷️</div><p class="mono text-[11px] font-bold text-slate-600 dark:text-slate-300">Version</p><p class="mono text-[10px] text-slate-400">M3</p></div>
    <div data-locker="3" class="rounded-xl border-2 border-dashed border-slate-200 bg-slate-50 p-3 text-center opacity-60 dark:border-slate-700 dark:bg-slate-800/50"><div class="text-lg">🩹</div><p class="mono text-[11px] font-bold text-slate-600 dark:text-slate-300">Patch</p><p class="mono text-[10px] text-slate-400">M4</p></div>
    <div data-locker="4" class="rounded-xl border-2 border-dashed border-slate-200 bg-slate-50 p-3 text-center opacity-60 dark:border-slate-700 dark:bg-slate-800/50"><div class="text-lg">⚙️</div><p class="mono text-[11px] font-bold text-slate-600 dark:text-slate-300">Config</p><p class="mono text-[10px] text-slate-400">M5</p></div>
    <div data-locker="5" class="rounded-xl border-2 border-dashed border-slate-200 bg-slate-50 p-3 text-center opacity-60 dark:border-slate-700 dark:bg-slate-800/50"><div class="text-lg">👻</div><p class="mono text-[11px] font-bold text-slate-600 dark:text-slate-300">Same PID</p><p class="mono text-[10px] text-slate-400">M7</p></div>
    <div data-locker="6" class="rounded-xl border-2 border-dashed border-slate-200 bg-slate-50 p-3 text-center opacity-60 dark:border-slate-700 dark:bg-slate-800/50"><div class="text-lg">📝</div><p class="mono text-[11px] font-bold text-slate-600 dark:text-slate-300">Report</p><p class="mono text-[10px] text-slate-400">M9</p></div>
  </div>
  <div class="mt-3 rounded-xl bg-amber-50 px-3 py-2 text-xs leading-relaxed text-amber-900 dark:bg-amber-500/10 dark:text-amber-200"><strong>Beginner rule:</strong> You don’t need to hack anything. <span class="font-mono font-bold">Version + SAPI + Config + PID</span> = L2 “likely exposed”. That’s a win that forces an emergency patch — you solved the lab!</div>
</div>

<!-- ═══════════════════ VICTORY (hidden) ═══════════════════ -->
<div id="victory-screen" class="hidden overflow-hidden rounded-[20px] border-2 border-amber-400 bg-gradient-to-br from-amber-400 via-orange-500 to-rose-500 p-[2px] shadow-2xl">
  <div class="rounded-[18px] bg-white p-6 text-center dark:bg-slate-900 sm:p-8">
    <div class="mx-auto grid h-16 w-16 place-items-center rounded-full bg-gradient-to-br from-amber-400 to-orange-500 text-2xl shadow-lg">🏆</div>
    <h3 class="game-font mt-3 text-xl font-bold text-slate-900 dark:text-white">YOU’RE A LEGEND — BOTH CVEs FOUND!</h3>
    <p class="mono mx-auto mt-2 max-w-xl text-xs leading-relaxed text-slate-600 dark:text-slate-300">You went from Script Kiddie to Legend, beat two boss CVEs, and collected evidence that would make any SOC lead proud. Take a screenshot — you earned it.</p>
    <div class="mx-auto mt-4 grid max-w-xl grid-cols-3 gap-3 text-center">
      <div class="rounded-xl bg-slate-50 p-3 dark:bg-slate-800"><p id="victory-time" class="text-sm font-bold text-slate-900 dark:text-white">—</p><p class="mono text-[11px] text-slate-500">Time</p></div>
      <div class="rounded-xl bg-slate-50 p-3 dark:bg-slate-800"><p class="text-sm font-bold text-slate-900 dark:text-white">2400 XP</p><p class="mono text-[11px] text-slate-500">Earned</p></div>
      <div class="rounded-xl bg-slate-50 p-3 dark:bg-slate-800"><p class="text-sm font-bold text-slate-900 dark:text-white">12/12</p><p class="mono text-[11px] text-slate-500">Missions</p></div>
    </div>
    <div class="mt-5 flex flex-wrap justify-center gap-2">
      <button type="button" onclick="shareVictory()" class="rounded-full bg-slate-900 px-5 py-2.5 text-xs font-bold text-white hover:bg-slate-800 dark:bg-white dark:text-slate-900">📤 Copy victory code</button>
      <button type="button" onclick="document.getElementById('wt-vault')?.scrollIntoView({behavior:'smooth'})" class="rounded-full border border-slate-200 bg-white px-5 py-2.5 text-xs font-semibold text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">📖 View full WALKTHROUGH.md</button>
      <button type="button" onclick="gameReset()" class="rounded-full border border-amber-300 bg-amber-50 px-5 py-2.5 text-xs font-bold text-amber-800 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300">🔄 Play again</button>
    </div>
    <p class="mono mt-3 text-[11px] text-slate-400">Easter egg: try the Konami code ↑↑↓↓←→←→BA on your keyboard ;)</p>
  </div>
</div>

<!-- ═══════════════════ WALKTHROUGH VAULT ═══════════════════ -->
<div id="wt-vault" class="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
  <div class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
    <div>
      <h3 class="game-font text-sm font-bold text-slate-900 dark:text-white">📚 WALKTHROUGH VAULT — the full guide (for deep divers)</h3>
      <p class="mono text-[11px] text-slate-400">This is the exact <code class="font-mono">WALKTHROUGH.md</code> from the repo, rendered. You don’t need it to win — the game above is enough. But it’s here if you want every detail, link, and packet dump.</p>
    </div>
    <div class="flex gap-2">
      <a href="?walkthrough=raw" target="_blank" class="mono rounded-full border border-slate-200 bg-white px-3 py-1.5 text-[11px] font-semibold text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">Raw markdown</a>
      <button type="button" onclick="document.getElementById('wt-content')?.scrollIntoView({behavior:'smooth'})" class="mono rounded-full bg-slate-900 px-3 py-1.5 text-[11px] font-bold text-white dark:bg-white dark:text-slate-900">Jump in ↓</button>
    </div>
  </div>
  <div id="wt-content" class="scroll-thin max-h-[60vh] overflow-y-auto px-6 py-6">
    <?= walkthrough_file_html() ?>
  </div>
</div>

<!-- quick glossary -->
<div class="rounded-2xl border border-amber-300 bg-amber-50 p-4 dark:border-amber-500/20 dark:bg-amber-500/10">
  <h3 class="text-sm font-bold text-amber-900 dark:text-amber-200">📚 Glossary — tap any confusing word in the game</h3>
  <div class="mt-3 grid gap-2 sm:grid-cols-3 text-xs leading-relaxed text-amber-900/80 dark:text-amber-200/80">
    <p><strong>CVE</strong> = bug ID. <strong>CVSS 9.2</strong> = super critical.</p>
    <p><strong>RCE</strong> = attacker runs code. Worst kind.</p>
    <p><strong>SAPI</strong> = how PHP runs: <code class="font-mono">fpm-fcgi</code> = web (needed).</p>
    <p><strong>memory_limit 256M</strong> = per-request RAM cap.</p>
    <p><strong>upload_progress On</strong> = feature that keeps pointer (109619).</p>
    <p><strong>pm.max_requests 0</strong> = worker never recycles — ghost stays!</p>
  </div>
</div>

<!-- CONFETTI LAYER -->
<div id="confetti-layer" class="pointer-events-none fixed inset-0 z-[9999] hidden"></div>

<script>
(function(){
  const LEVELS = [
    {name:'Script Kiddie', xp:0},
    {name:'Packet Peeker', xp:150},
    {name:'Recon Ranger', xp:300},
    {name:'Version Slayer', xp:500},
    {name:'Patch Detective', xp:700},
    {name:'Config Ninja', xp:950},
    {name:'Evidence Hoarder', xp:1150},
    {name:'Ghost Tamer', xp:1450},
    {name:'Memory Breaker', xp:1750},
    {name:'Report Captain', xp:1950},
    {name:'Threat Hunter', xp:2150},
    {name:'Patch Lord', xp:2300},
    {name:'★ LEGEND', xp:2400},
  ];
  const MISSIONS = [
    {
n:1, icon:'🌅', title:'Wake Up, Neo', subtitle:'Is anyone home? · Health checks',
xp:100, diff:'★☆☆', badge:'🌅 First Light', badgeName:'First Light', color:'from-emerald-500 to-teal-600',
sage:'“First rule of hacking: is it even plugged in? Check healthz, ping the box, see if supervisord is breathing. Four 200s and we’re in business.”',
brief:'<p><strong>You just got paged at 3AM.</strong> Before you hunt CVEs, make sure the lab is actually running. Real-world parallel: you’d start with <code class="font-mono font-bold">/healthz</code> and <code class="font-mono">supervisorctl status</code> — same instinct as checking if a patient has a pulse.</p><p class="mt-2"><strong>What you’ll do:</strong> hit the container, see it answer, note the four supervisord processes. Takes 2 minutes. Gets you your first badge.</p>',
objective:['Open <code class="font-mono">GET /healthz</code> → expect 200 OK (our liveness probe)','Run <code class="font-mono">supervisorctl status</code> inside container → 4× RUNNING','Ping <code class="font-mono">127.0.0.1:8080</code> and note latency','Checkpoint: screenshot 4×200 or copy the JSON'],
commands:[
  {label:'curl /healthz', cmd:'curl -i http://127.0.0.1:8080/healthz', expect:'200 OK + nginx', run:(term)=>fetch('/healthz').then(r=>r.text().then(t=> termPrint(term, '→ HTTP '+r.status+'\\n'+ t.slice(0,600))))},
  {label:'supervisorctl status', cmd:'docker exec php2shell supervisorctl status', expect:'4× RUNNING (nginx, php-fpm, app, super)', run:(term)=> termPrint(term, 'nginx      RUNNING\\nphp-fpm    RUNNING  pid 12\\napp        RUNNING\\n— if you see these, you’re good! Run it inside the container with:\\n  docker exec -it php2shell supervisorctl status')},
  {label:'Check who is home', cmd:'curl -s http://127.0.0.1:8080/healthz | head', expect:'Nimbus JSON with uptime', run:(term)=>fetch('/healthz').then(r=>r.text()).then(t=>{try{termPrint(term, JSON.stringify(JSON.parse(t),null,2))}catch(e){termPrint(term,t.slice(0,900))}})},
],
quiz:{q:'What does <code class="font-mono">/healthz</code> prove?', opts:['The PHP CVEs exist','The container is up and nginx can reach FPM','You have RCE'], a:1, ok:'Exactly — healthz is just “is the patient alive?” Not “is it vulnerable.”', bad:['Nope — you need version+config for that. Healthz just says “I’m awake.”','Bingo. 200 = nginx→FPM is breathing. Now we hunt.','Whoa, not yet! A 200 doesn’t mean hacked — we’ll learn why in M8.']}
    },
    {
n:2, icon:'👃', title:'Sniff the Wires', subtitle:'What leaked? · Black-box recon',
xp:120, diff:'★★☆', badge:'👃 Sniffer', badgeName:'Sniffer', color:'from-sky-500 to-indigo-600',
sage:'“Attackers start outside. No creds, no shell — just headers, favicons, and vibes. What does nginx blab about PHP without you even logging in?”',
brief:'<p><strong>Think like an outsider.</strong> Before you touch code, look at the outside: HTTP headers, <code class="font-mono">X-Powered-By</code>, favicon, error pages. In real life this tells you if a target is even <em>worth</em> testing — and draws your <code class="font-mono">nginx:80 → 127.0.0.1:9000</code> map.</p><p class="mt-2"><strong>Win:</strong> you’ll spot the PHP version leak and draw the infra diagram. One header = one clue.</p>',
objective:['Run <code class="font-mono">curl -I /</code> and list every header with <code class="font-mono">php</code>/<code class="font-mono">nginx</code>/<code class="font-mono">X-</code>','Draw ASCII map: <code class="font-mono">you → :8080 → nginx:80 → 127.0.0.1:9000 (FPM)</code>','Note what an outsider <em>can’t</em> see (patch level, config)'],
commands:[
  {label:'curl -I /', cmd:'curl -I http://127.0.0.1:8080/', expect:'X-Powered-By: PHP/8.4.26 maybe?', run:(term)=>fetch('/',{method:'HEAD'}).then(r=>{let h=''; r.headers.forEach((v,k)=>h+=k+': '+v+'\\n'); termPrint(term, 'Status: '+r.status+'\\n'+h+'\\n— look for X-Powered-By / Server leaking PHP/nginx');})},
  {label:'curl -i /', cmd:'curl -i http://127.0.0.1:8080/', expect:'Full response with headers + body', run:(term)=>fetch('/').then(r=>r.text().then(t=> termPrint(term, t.slice(0,900)+'\\n\\n— search for “php” “nginx” “nimbus” in headers above')))},
  {label:'What’s behind?', cmd:'curl -s http://127.0.0.1:8080/healthz', expect:'JSON proving nginx→FPM hop', run:(term)=>fetch('/healthz').then(r=>r.text().then(t=>termPrint(term,t)))},
],
quiz:{q:'You see <code class="font-mono">Server: nginx</code> but no <code class="font-mono">X-Powered-By</code>. What now?', opts:['Give up — not PHP','Check favicon, errors, /healthz, and try phpinfo-ish paths','Assume it’s patched'], a:1, ok:'Yes! Leaks hide in weird places — favicon hash, error pages, API. One missing header doesn’t clear a host.', bad:['Never — favicons and error pages snitch too.','Pro move — headers are just one signal. Keep sniffing.','Version strings alone can lie (backports). Don’t trust them yet.']}
    },
    {
n:3, icon:'🔍', title:'Name the Beast', subtitle:'Who are you? · Fingerprint engine',
xp:150, diff:'★★☆', badge:'🏷️ Beast Tamer', badgeName:'Beast Tamer', color:'from-amber-500 to-orange-600',
sage:'“Version numbers are gossip. We need receipts: engine string, SAPI, binary hash. Is it 8.4.26 before the fix? And is it <em>fpm</em> (risky) or cli (meh)?”',
brief:'<p><strong>Fingerprint = who are we dealing with?</strong> You’ll run <code class="font-mono">/healthz</code> and <code class="font-mono">phpversion()</code> paths to get <code class="font-mono">8.4.26</code> + <code class="font-mono">fpm-fcgi</code>. Then you’ll grab <code class="font-mono">docker inspect</code> + base digest — the “photo ID” of this build.</p><p class="mt-2">Why it matters: both CVEs need <span class="font-bold">pre-patch + FPM SAPI</span>. CLI doesn’t count. mod_php would be even worse, but here it’s FPM.</p>',
objective:['Record <code class="font-mono">PHP 8.4.26</code> + <code class="font-mono">fpm-fcgi</code> from healthz','Run <code class="font-mono">docker inspect</code> → Image ID + base digest','Note: why <code class="font-mono">cli</code> wouldn’t be exploitable here'],
commands:[
  {label:'phpversion()', cmd:'curl http://127.0.0.1:8080/healthz', expect:'8.4.26 + fpm-fcgi', run:(term)=>fetch('/healthz').then(r=>r.text()).then(t=>{try{const j=JSON.parse(t);termPrint(term, 'Version: '+(j.php||j.version||'?')+'\\nSAPI: '+(j.sapi||j.api||'?')+'\\nFull: '+JSON.stringify(j,null,2))}catch(e){termPrint(term,t.slice(0,900))}})},
  {label:'Show PHP info', cmd:'curl http://127.0.0.1:8080/ | grep -i php', expect:'Leaked version in HTML/body', run:(term)=>fetch('/').then(r=>r.text().then(t=>{let m=t.match(/php[^<]{0,80}/gi); termPrint(term, (m? m.join('\\n') : 'No obvious leak in / — try /healthz or view source') + '\\n\\nSnippet:\\n'+ t.slice(0,700));}))},
  {label:'docker inspect', cmd:'docker inspect php2shell --format {{.Id}}', expect:'sha256:… (image digest)', run:(term)=> termPrint(term, 'Run this in your terminal (not here):\\n  docker inspect php2shell --format \"{{.Id}}\"\\n  docker inspect php2shell | grep -i digest\\n\\nCopy the sha256 — that’s your baseline evidence.')},
],
quiz:{q:'You fingerprinted <code class="font-mono">8.4.26 cli</code>. Are we vulnerable?', opts:['Yes, same bug','No — need fpm/mod_php (web SAPI)','Maybe, need memory_limit'], a:1, ok:'Right — these CVEs need a web SAPI (FPM/mod_php). CLI is a different world.', bad:['Trick! CLI ≠ web. Same engine, different doors.','Exactly — FPM or mod_php is where the request lives.','Config matters next (M5), but SAPI is gate #1.']}
    },
    {
n:4, icon:'🗄️', title:'Cold Case Files', subtitle:'Is it patched? · GHSA → CVE triage',
xp:180, diff:'★★★', badge:'🕵️ Patch Detective', badgeName:'Patch Detective', color:'from-violet-600 to-indigo-600',
sage:'“PHP shipped 8.4.27 to fix this. Is our 8.4.26 before or after? Don’t guess — map GHSA → CVE → tag and check backports. Version strings can lie.”',
brief:'<p><strong>Patch triage = are we on the wrong side of history?</strong> <code class="font-mono">8.4.26</code> was released <em>before</em> the fixing commits for both CVEs; <code class="font-mono">8.4.27</code> (and 8.5.12/8.3.36/8.2.35) is after. You’ll map <span class="font-mono font-bold">GHSA-w8hw-w9fx-j79w → CVE-2026-109618</span> and <span class="font-mono font-bold">GHSA-6wmf-4rv5-p3rp → CVE-2026-109619</span> and see the fix landed in 8.4.27.</p><p class="mt-2">Real-world twist: some “old-looking” versions are actually backport-patched (Debian, RHEL). You’ll learn to check changelogs, not just numbers.</p>',
objective:['Confirm <code class="font-mono">8.4.26 < 8.4.27</code> → unpatched for BOTH CVEs','Map GHSA advisories to CVE IDs (links in vault below)','Note backport check: <code class="font-mono">changelog.Debian.gz</code> / <code class="font-mono">rpm -q --changelog</code>'],
commands:[
  {label:'CVE IDs', cmd:'cat cve-demonstrations/README.md | grep CVE', expect:'CVE-2026-109618 + 109619', run:(term)=> termPrint(term, 'In terminal:\\n  cat cve-demonstrations/README.md\\n  cat cve-demonstrations/CVE-2026-109618.md | head -n 30\\n\\nOr click: WALKTHROUGH VAULT ↓ shows GHSA links.')},
  {label:'Check vendor fix', cmd:'git log --oneline --grep=109618', expect:'Fix commit in php-src', run:(term)=> termPrint(term, 'In repo:\\n  git log --oneline --all --grep=10961 | head\\n  git show <fix-commit> --stat\\n\\nFix should be AFTER 8.4.26 tag, included in 8.4.27.')},
  {label:'Is 8.4.26 old?', cmd:'php -r "echo version_compare(\\"8.4.26\\",\\"8.4.27\\");"', expect:'-1 (older)', run:(term)=> termPrint(term, '8.4.26 < 8.4.27 → unpatched ✅\\n8.4.27 / 8.5.12 / 8.3.36 / 8.2.35 → fixed\\nBackports: check distro changelog, not just php -v')},
],
quiz:{q:'Target reports <code class="font-mono">PHP 8.4.26</code> but the admin says “we backported the fix.” What do you do?', opts:['Mark safe','Ask for changelog + fixing commit + build digest','Exploit to prove'], a:1, ok:'Yes — version strings can lie. You need the receipt: changelog, commit, or sanitizer trace.', bad:['Never — backports are real. You need proof.','That’s the pro move — receipts over rumors.','No exploits needed — and it’d be noisy/risky. L2 is enough.']}
    },
    {
n:5, icon:'⚙️', title:'Config Chaos', subtitle:'Can it happen here? · Attack requirements',
xp:200, diff:'★★★', badge:'⚙️ Config Ninja', badgeName:'Config Ninja', color:'from-slate-700 to-slate-900',
sage:'“Being unpatched isn’t enough. Can an attacker <em>reach</em> the bug? For 109618 you need uploads; for 109619 you need that spooky setting left On with immortal workers.”',
brief:'<p><strong>Attack requirements = is the door not just unlocked, but reachable?</strong></p><ul class="list-disc pl-5"><li><strong>CVE-2026-109618 (Memory Leviathan):</strong> needs <code class="font-mono">memory_limit 256M</code>, multipart allowed (<code class="font-mono">post_max_size 24M</code>), attacker can send big body.</li><li><strong>CVE-2026-109619 (Ghost Worker):</strong> needs <code class="font-mono">session.upload_progress.enabled=On</code> + <code class="font-mono">pm.max_requests=0</code> (workers never recycle) + attacker can hit same PID.</li></ul><p class="mt-2">You’ll pull <code class="font-mono">php.ini</code> and <code class="font-mono">php-fpm.conf</code> to see both are true in this lab.</p>',
objective:['Grab <code class="font-mono">memory_limit</code>, <code class="font-mono">post_max_size</code>, <code class="font-mono">upload_max_filesize</code>','Grab <code class="font-mono">session.upload_progress.enabled</code> (109619!)','Grab <code class="font-mono">pm = static</code>, <code class="font-mono">pm.max_children 1</code>, <code class="font-mono">pm.max_requests 0</code>'],
commands:[
  {label:'php.ini', cmd:'cat php2shell-lab/php2shell.ini', expect:'memory_limit 256M, post_max_size 24M, upload_progress On', run:(term)=>fetch('index.php?api=stats').then(r=>r.json()).then(j=> termPrint(term, 'Live check via /api/stats or terminal:\\n  docker exec php2shell cat /usr/local/etc/php/conf.d/php2shell.ini\\n  docker exec php2shell php -i | grep -i \"memory_limit\\|post_max\\|upload_progress\"')).catch(()=> termPrint(term, 'In terminal:\\n  docker exec php2shell cat /usr/local/etc/php/conf.d/php2shell.ini\\n  docker exec php2shell php -i | grep -i memory'))},
  {label:'FPM pool', cmd:'cat php-fpm.conf | grep pm.', expect:'pm=static, max_children 1, max_requests 0', run:(term)=> termPrint(term, 'In terminal:\\n  docker exec php2shell cat /usr/local/etc/php-fpm.d/www.conf | grep -E \"pm|max_request|listen\"\\n\\nFor 109619 you NEED max_requests=0 (immortal workers) — that’s why the ghost stays.')},
  {label:'Live stats', cmd:'curl http://127.0.0.1:8080/api/stats', expect:'JSON with limits', run:(term)=>fetch('index.php?api=stats').then(r=>r.json().then(j=> termPrint(term, JSON.stringify(j,null,2))).catch(()=>fetch('index.php?api=stats').then(r=>r.text().then(t=>termPrint(term,t)))))},
],
quiz:{q:'Which config makes <strong>Ghost Worker (109619)</strong> possible?', opts:['memory_limit 256M','pm.max_requests=0 + upload_progress On','expose_php On'], a:1, ok:'Yes — immortal workers (0) + that progress feature = ghost can linger.', bad:['That’s Leviathan (109618).','Nailed it — the ghost needs immortality + that feature.','That just leaks version — not RCE.']}
    },
    {
n:6, icon:'📸', title:'Bag the Evidence', subtitle:'Pics or it didn’t happen · Baseline collector',
xp:180, diff:'★★☆', badge:'📸 Evidence Hoarder', badgeName:'Evidence Hoarder', color:'from-emerald-600 to-cyan-600',
sage:'“No screenshot, no finding. Run the collector, hash your files, and bag the baseline. This is what separates tourists from pros.”',
brief:'<p><strong>Evidence ladder:</strong> L0 rumor → L1 version → <span class="rounded bg-emerald-100 px-1 font-bold text-emerald-800">L2 likely exposed (YOUR GOAL)</span> → L3 sanitizer proof → L4 full exploit (not needed!).</p><p class="mt-2">You’ll run <code class="font-mono">collect_runtime.py</code> to produce <code class="font-mono">baseline.json</code> + hashes. Keep image digests — that’s your chain of custody.</p>',
objective:['Run <code class="font-mono">python3 collect_runtime.py</code> → baseline.json','Record <code class="font-mono">sha256</code> of configs + image digest','Understand: why L2 is enough to force an emergency patch'],
commands:[
  {label:'Collect baseline', cmd:'python3 collect_runtime.py', expect:'baseline.json + hashes written', run:(term)=> termPrint(term, 'In repo:\\n  python3 collect_runtime.py\\n  cat baseline.json | head -n 60\\n  sha256sum baseline.json php2shell-lab/php2shell.ini\\n\\nKeep these — they’re your receipts.')},
  {label:'What’s in baseline?', cmd:'cat baseline.json | jq', expect:'version, sapi, ini, fpm, digests', run:(term)=> termPrint(term, 'baseline.json should contain:\\n  php_version, sapi, ini (memory_limit, upload_progress), fpm (pm.*), digests\\n  → this is your L2 packet.')},
  {label:'Digests', cmd:'docker inspect php2shell | grep Id', expect:'sha256:…', run:(term)=> termPrint(term, 'docker inspect php2shell --format \"{{.Id}} {{.Config.Image}}\"\\nSave this — proves which vulnerable image you tested.')},
],
quiz:{q:'What’s the <em>minimum</em> to file a credible finding?', opts:['“It crashed, so it’s hacked”','L2: version + SAPI + attack requirements + baseline hashes','Full RCE exploit with shell'], a:1, ok:'Yes — L2 (“likely exposed”) is enough. No fireworks needed.', bad:['Crash ≠ RCE — we’ll prove that in M8.','Exactly — L2 is the pro standard. Exploit is extra credit.','Overkill and risky. L2 moves faster.']}
    },
    {
n:7, icon:'👻', title:'GHOST WORKER — BOSS FIGHT', subtitle:'Same PID or it didn’t happen · CVE-2026-109619',
xp:350, diff:'★★★★', badge:'👻 Ghostbuster', badgeName:'Ghostbuster', color:'from-rose-600 to-orange-600',
sage:'“This is it — the haunting. Pin ONE immortal worker, hit it twice, and watch the PIDs. Same PID = ghost can possess the next request. Recycle the worker = ghost dies. That’s your proof.”',
brief:'<p><strong>CVE-2026-109619 boss mechanics:</strong> Request A leaves a freed global. Request B on the <em>same PID</em> uses it → leak/RCE. If the worker recycles, the ghost is gone.</p><p><strong>Your experiment:</strong> set <code class="font-mono">pm=static, max_children=1, max_requests=0</code> (already done in lab). Instrument FPM to log <code class="font-mono">pid</code> per request. Send A→B and show <span class="font-bold text-rose-600">same PID</span>. Then set <code class="font-mono">pm.max_requests=1</code> and show it flips → ghost can’t survive. That’s FPM-validated L2!</p><p class="mt-2 mono rounded-lg bg-rose-50 px-3 py-2 text-xs text-rose-900 dark:bg-rose-500/10 dark:text-rose-200">No exploit needed — just PIDs and fresh-worker control. That’s how you win without being reckless.</p>',
objective:['Pin 1 worker (static, children=1, max_requests=0)','Log PID per request (instrument pool)','Show A→B same PID → 109619 exposure','Control: max_requests=1 → PID changes → not exploitable'],
commands:[
  {label:'Show FPM config', cmd:'grep -E "pm\\." /usr/local/etc/php-fpm.d/www.conf', expect:'pm=static, max_children 1, max_requests 0', run:(term)=> termPrint(term, 'docker exec php2shell cat /usr/local/etc/php-fpm.d/www.conf | grep -E "pm|max_request"\\n\\nIf max_requests=0, workers NEVER recycle — ghost lives forever. That’s the lab setup.')},
  {label:'Log PIDs', cmd:'curl x2 → compare pid', expect:'Same pid = vulnerable path', run:(term)=> termPrint(term, 'Add to pool config:\\n  access.log = /proc/self/fd/2\\n  access.format = \\"%{HTTP_X-Request-Id}i pid:%p\"\\nThen:\\n  curl -H \"X-Request-Id: A\" http://127.0.0.1:8080/\\n  curl -H \"X-Request-Id: B\" http://127.0.0.1:8080/\\n  docker logs php2shell | grep pid\\n→ same pid = same worker = ghost can strike')},
  {label:'Control test', cmd:'max_requests=1 → pid flips', expect:'Different pid = ghost dies', run:(term)=> termPrint(term, 'Change www.conf: pm.max_requests=1, restart:\\n  docker exec php2shell supervisorctl restart php-fpm\\nRe-run two curls → pids differ → control proves your test is real, not luck.')},
],
quiz:{q:'You saw two requests with <strong>different PIDs</strong>. What does it mean?', opts:['Proves CVE-2026-109619','Proves nothing — ghost died with worker, need same PID','Means it’s patched'], a:1, ok:'Right — 109619 needs same worker. Different PID = ghost didn’t survive. You need to pin 1 worker.', bad:['Nope — needs same worker to reuse freed pointer.','Exactly — you need to force same PID (pm=static, 1 child).','Not necessarily — you just didn’t hit the haunted worker.']}
    },
    {
n:8, icon:'🧠', title:'MEMORY LEVIATHAN — BOSS FIGHT', subtitle:'500 ≠ pwned · CVE-2026-109618',
xp:350, diff:'★★★★', badge:'🧠 Memory Master', badgeName:'Memory Master', color:'from-indigo-600 to-violet-700',
sage:'“Everyone thinks a 500 error = hack. Nah. Trigger OOM on BOTH the vulnerable and patched build — you’ll get the SAME 500. That’s the lesson: crashes aren’t exploits.”',
brief:'<p><strong>CVE-2026-109618 boss mechanics:</strong> huge allocation hits <code class="font-mono">memory_limit 256M</code> inside engine → <code class="font-mono">longjmp</code> → uninitialized memory path → RCE.</p><p>But: PHP’s normal <code class="font-mono">Allowed memory size exhausted</code> happens on <em>both</em> 8.4.26 and 8.4.27. So a plain 500 proves nothing!</p><p class="mt-2"><strong>Your experiment:</strong> trigger memory pressure on this (8.4.26) and on a patched rebuild (<code class="font-mono">--build-arg PHP_IMAGE=php:8.4.27-fpm-alpine</code>). Both 500 the same → you teach the team what <em>isn’t</em> proof. Real L3 proof needs ASAN trace of uninitialized use (advanced).</p>',
objective:['Trigger OOM (big upload/body) → see 500 / memory exhausted on 8.4.26','Rebuild with <code class="font-mono">php:8.4.27-fpm-alpine</code> and repeat → same 500','Conclude: 500 alone is NOT RCE — need sanitizer trace for L3'],
commands:[
  {label:'Trigger OOM', cmd:'curl --data-binary @big.bin http://127.0.0.1:8080/', expect:'500 or memory exhausted (expected!)', run:(term)=> termPrint(term, 'Create a big body (24M) and hit memory_limit:\\n  dd if=/dev/zero of=/tmp/big.bin bs=1M count=24\\n  curl -X POST --data-binary @/tmp/big.bin http://127.0.0.1:8080/ -i\\n→ expect memory error — that is NORMAL on both builds.')},
  {label:'Rebuild patched', cmd:'docker build --build-arg PHP_IMAGE=php:8.4.27-fpm-alpine -t php2shell:patched .', expect:'Both 500 → 500≠RCE', run:(term)=> termPrint(term, 'Rebuild with fix:\\n  docker build --build-arg PHP_IMAGE=php:8.4.27-fpm-alpine -t php2shell:patched php2shell-lab\\n  docker run -p 8081:80 php2shell:patched\\n  curl same big.bin to :8081 → still 500 → lesson learned!')},
  {label:'What is real proof?', cmd:'asan trace', expect:'ASAN uninitialized use (advanced)', run:(term)=> termPrint(term, 'Real L3 proof (advanced): build with -fsanitize=address,memory, keep source revision, run vendor regression test → ASAN trace of uninit read after longjmp.\\nNo trace = L2 only — which is still a win!')},
],
quiz:{q:'You got a 500 after a huge POST. Did you prove RCE?', opts:['Yes — server crashed','No — need sanitizer trace; 500 happens on patched too','Yes if it says memory exhausted'], a:1, ok:'Yes — 500 is expected. Real proof is ASAN uninit trace. You just learned what NOT to report.', bad:['Nope — crashes happen on fixed builds too.','Exactly — both builds 500. You need the trace.','That string is normal PHP — not the bug.']}
    },
    {
n:9, icon:'📝', title:'Write It Like You Mean It', subtitle:'One-page L2 report · Make them patch NOW',
xp:250, diff:'★★★', badge:'📝 Report Captain', badgeName:'Report Captain', color:'from-emerald-600 to-teal-600',
sage:'“You have the receipts. Now write the one-pager that makes a manager approve an emergency patch at 4AM. Clear, calm, no hype.”',
brief:'<p><strong>Your report needs:</strong> asset + version/SAPI + GHSA/CVE + attack requirements + evidence + caveat + fix. One page. Link your <code class="font-mono">baseline.json</code> + digests.</p><p class="mt-2">Tone: <span class="font-bold">“Likely exposed — meets all preconditions, no exploit tested.”</span> That’s credible and fast. You’ll cite <code class="font-mono">cve.org/CVERecord?id=CVE-2026-10961*</code> and the GHSA advisories.</p>',
objective:['Draft L2 report (asset, version, CVE, SAPI, config, hashes, fix)','Include caveat: “no exploit, backport not excluded without changelog”','State fix: upgrade to 8.4.27/8.5.12/8.3.36/8.2.35 + restart workers'],
commands:[
  {label:'Report template', cmd:'cat SOLUTION.md | head -n 80', expect:'One-page template', run:(term)=> termPrint(term, 'In repo:\\n  cat SOLUTION.md\\n  cat WALKTHROUGH.md | grep -A2 \"L2 report\"\\n\\nCopy the template and fill with YOUR baseline values.')},
  {label:'GHSA links', cmd:'open advisories', expect:'GHSA-w8hw… + GHSA-6wmf…', run:(term)=> termPrint(term, 'Links (open in browser):\\n  github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w (109618)\\n  github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp (109619)\\n  cve.org/CVERecord?id=CVE-2026-109618\\n  cve.org/CVERecord?id=CVE-2026-109619')},
  {label:'Fix line', cmd:'echo fixed versions', expect:'8.4.27 / 8.5.12 / 8.3.36 / 8.2.35', run:(term)=> termPrint(term, 'Fixed in:\\n  8.4.27, 8.5.12, 8.3.36, 8.2.35\\nAction: upgrade image + restart FPM workers + re-run baseline.')},
],
quiz:{q:'Best L2 summary line?', opts:['“We pwned it, give us a bounty”','“Likely exposed: 8.4.26 fpm-fcgi + upload_progress On + pm.max_requests 0 + baseline hashes — recommend emergency patch, no exploit tested”','“It’s probably fine”'], a:1, ok:'That’s the one — specific, provable, actionable. No hype.', bad:['Too hype — you need receipts, not vibes.','Perfect — that’s how pros force a patch without drama.','Nope — you have L2 proof. Don’t undersell it.']}
    },
    {
n:10, icon:'🕵️', title:'Hunt in the Dark', subtitle:'Detection · What would logs show?',
xp:150, diff:'★★☆', badge:'🔍 Threat Hunter', badgeName:'Threat Hunter', color:'from-slate-700 to-indigo-700',
sage:'“Flip to defense: if someone tried this in prod, what would you hunt? Best signal isn’t 500s — it’s PHP worker → shell.”',
brief:'<p><strong>Detection hunt:</strong> grease the logs and think: <code class="font-mono">zgrep -iE \"php.*sh|CVE-2026-10961\" /var/log/php*</code>, WAF hits on huge POSTs, FPM slowlog, and the golden rule: <span class="font-bold text-indigo-600">PHP process spawning a shell</span> is always bad.</p>',
objective:['List log sources: nginx access, FPM, syslog, auditd','Run grep hunt for php→shell, huge POSTs, OOM','Note best signal: worker → shell (EDR)'],
commands:[
  {label:'Log locations', cmd:'ls /var/log/nginx /var/log/php*', expect:'access.log, error.log, fpm.log', run:(term)=> termPrint(term, 'Common spots:\\n  /var/log/nginx/access.log\\n  /var/log/php*-fpm.log\\n  /var/log/syslog, audit.log\\n  EDR: process tree parent=php-fpm')},
  {label:'Hunt queries', cmd:'zgrep php /var/log/nginx/access.log | head', expect:'Huge POSTs, upload_progress', run:(term)=> termPrint(term, 'Hunt ideas:\\n  zgrep -iE \"upload_progress|POST.*24M\" /var/log/nginx/access.log*\\n  journalctl _COMM=php-fpm | head\\n  Best: look for php-fpm PID → /bin/sh (that’s compromise)')},
  {label:'What matters?', cmd:'echo best signal', expect:'PHP → shell', run:(term)=> termPrint(term, 'Best signal: PHP worker execs shell.\\nMedium: repeated huge multipart POSTs from one IP.\\nWeak: single 500 (noise).')},
],
quiz:{q:'Strongest detection for successful RCE?', opts:['A 500 error','PHP worker process spawns /bin/sh or curl to internal host','Many 200s'], a:1, ok:'Yes — worker→shell is compromise. Everything else is just “someone tried.”', bad:['500 is noise — happens normally.','That’s the jackpot — EDR should alert instantly.','Normal traffic — not signal.']}
    },
    {
n:11, icon:'🛡️', title:'Patch & Flex', subtitle:'Rebuild 8.4.27 · Prove it’s dead',
xp:200, diff:'★★☆', badge:'🛡️ Patch Lord', badgeName:'Patch Lord', color:'from-emerald-600 to-cyan-600',
sage:'“Now you patch and prove it. Same tests, now they should fail to reproduce. Keep the digests — before/after is how you close the ticket.”',
brief:'<p><strong>Patch & retest:</strong> rebuild with <code class="font-mono">--build-arg PHP_IMAGE=php:8.4.27-fpm-alpine</code> (or 8.5.12/8.3.36/8.2.35), restart workers, re-run missions 2–8. Vulnerabilities should be gone; your evidence should stay.</p>',
objective:['Rebuild: <code class="font-mono">docker build --build-arg PHP_IMAGE=php:8.4.27-fpm-alpine</code>','Restart + re-run baseline + PID test → no longer same-PID exploitable','Record new digest + compare'],
commands:[
  {label:'Rebuild', cmd:'docker build -t php2shell:fixed --build-arg PHP_IMAGE=php:8.4.27-fpm-alpine .', expect:'New image with 8.4.27', run:(term)=> termPrint(term, 'docker build --build-arg PHP_IMAGE=php:8.4.27-fpm-alpine -t php2shell:fixed php2shell-lab\\ndocker run -p 8081:80 php2shell:fixed\\ncurl http://127.0.0.1:8081/healthz → 8.4.27')},
  {label:'Retest', cmd:'curl /healthz + pid test on :8081', expect:'Version 8.4.27 + PID test clean', run:(term)=> termPrint(term, 'Same commands on :8081 → version bumps to 8.4.27, patch triage now says “fixed”, PID ghost gone (freed pointer cleared).')},
  {label:'Digests', cmd:'docker inspect | grep Id', expect:'Before/after digests', run:(term)=> termPrint(term, 'Save both:\\n  docker inspect php2shell --format {{.Id}} > before.txt\\n  docker inspect php2shell:fixed --format {{.Id}} > after.txt\\n  diff before.txt after.txt')},
],
quiz:{q:'After patch, what should you see?', opts:['Same 500 exploit still works','Version 8.4.27 + same tests no longer show exposure','No need to retest'], a:1, ok:'Yes — version flips to fixed and exposure conditions are mitigated.', bad:['No — fix clears the bug.','Exactly — that’s how you close the incident.','Always retest — trust but verify.']}
    },
    {
n:12, icon:'🧹', title:'Ghost Protocol', subtitle:'Leave no trace · Teardown',
xp:100, diff:'★☆☆', badge:'🧹 Ghosted', badgeName:'Ghosted', color:'from-slate-600 to-slate-800',
sage:'“Good hunters leave no mess. Delete the vulnerable image, kill the container, wipe the big files. Lab clean = job done.”',
brief:'<p><strong>Teardown:</strong> <code class="font-mono">docker rm -f php2shell</code> + <code class="font-mono">docker rmi php2shell:fixed</code> + delete <code class="font-mono">/tmp/big.bin</code>. If you used a VM, snapshot revert. No vulnerable image lying around.</p>',
objective:['<code class="font-mono">docker rm -f php2shell php2shell:fixed</code>','<code class="font-mono">rm /tmp/big.bin baseline.json</code> (or archive)','Final check: <code class="font-mono">docker ps -a | grep php2shell</code> → empty'],
commands:[
  {label:'Teardown', cmd:'docker rm -f php2shell', expect:'Container gone', run:(term)=> termPrint(term, 'docker rm -f php2shell php2shell:fixed 2>/dev/null; docker rmi php2shell:fixed 2>/dev/null; rm -f /tmp/big.bin\\ndocker ps -a | grep php2shell || echo \"clean ✅\"')},
  {label:'Verify clean', cmd:'docker ps -a | grep php2shell', expect:'No output = clean', run:(term)=> termPrint(term, 'If no output, you’re ghosted. Archive your report + baseline.json elsewhere if you need it.')},
  {label:'You did it?', cmd:'echo done', expect:'Victory screen', run:(term)=> termPrint(term, '🎉 All 12 done? Scroll up — your Victory screen should be showing! Copy your victory code and flex.')},
],
quiz:{q:'Why teardown?', opts:['To hide evidence','So no one (including you) accidentally runs a vulnerable image later','It patches prod'], a:1, ok:'Safety — vulnerable images shouldn’t linger on your laptop.', bad:['No — keep your report. Delete the *vulnerable runtime*.','Yes — don’t leave loaded guns around.','No — teardown is local hygiene. Prod patch was M11.']}
    },
  ];

  // state
  let state = {xp:0, done:{}, avatar:'🐱', quizOk:{}, cmdOk:{}, streak:0, start:Date.now()};
  try{
    const s=JSON.parse(localStorage.getItem('game-state-v2')||'null');
    if(s){ state={...state, ...s}; }
  }catch(e){}
  let current = null;
  let speedrunOn=false, speedrunTimer=null;

  function levelFor(xp){
    let lvl=1, name=LEVELS[0].name, next=LEVELS[1];
    for(let i=0;i<LEVELS.length;i++){
      if(xp >= LEVELS[i].xp){ lvl=i+1; name=LEVELS[i].name; next=LEVELS[i+1]||null; }
    }
    return {lvl,name,next};
  }
  function save(){
    try{ localStorage.setItem('game-state-v2', JSON.stringify(state)); }catch(e){}
  }
  function setAvatar(a){
    state.avatar=a; save();
    document.getElementById('game-avatar').textContent=a;
    document.querySelectorAll('.avatar-btn').forEach(b=>{
      const on=b.dataset.avatar===a;
      b.className=on
        ? 'avatar-btn group rounded-2xl border-2 border-amber-400 bg-amber-50 p-4 text-left shadow-sm dark:bg-amber-500/10'
        : 'avatar-btn group rounded-2xl border border-slate-200 bg-white p-4 text-left hover:border-slate-300 dark:border-slate-700 dark:bg-slate-800';
      b.querySelector('p:last-child').textContent= on ? '✓ SELECTED' : 'click to equip';
      b.querySelector('p:last-child').className= on ? 'mono mt-1 text-[10px] font-bold text-emerald-600' : 'mono mt-1 text-[10px] text-slate-400';
    });
  }
  document.querySelectorAll('.avatar-btn').forEach(b=> b.addEventListener('click', ()=> setAvatar(b.dataset.avatar)));

  function termPrint(term, text){
    const line = document.createElement('div');
    line.textContent = text;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
    // also mark command ok for current mission
    if(current!==null){
      state.cmdOk[current]=true; save();
      updateClaim();
    }
  }
  window.termPrint = termPrint;

  function updateXP(){
    const lv=levelFor(state.xp);
    document.getElementById('game-avatar').textContent=state.avatar;
    document.getElementById('game-xp').textContent=state.xp;
    document.getElementById('game-level').textContent=lv.lvl;
    document.getElementById('game-level-name').textContent=lv.name;
    const total=2400;
    const pct=Math.min(100, Math.round(state.xp/total*100));
    document.getElementById('game-xp-fill').style.width=pct+'%';
    const doneCount=Object.keys(state.done).length;
    document.getElementById('game-progress-text').textContent=doneCount+'/12 missions';
    document.getElementById('game-pct').textContent=pct+'%';
    document.getElementById('game-streak').textContent='🔥 '+ state.streak +' streak';
    document.getElementById('locker-count').textContent= Math.min(6, Math.floor(doneCount/2)+ (doneCount>=9?1:0));
    if(lv.next) document.getElementById('game-next-lvl').textContent='Next: '+lv.next.name+' ('+lv.next.xp+' XP)';
    else document.getElementById('game-next-lvl').textContent='★ MAX LEVEL — LEGEND';
    // path fill
    const pathPct = Math.round(doneCount/12*100);
    const fill=document.getElementById('game-path-fill');
    if(fill) fill.style.height= pathPct+'%';
    // locker
    document.querySelectorAll('[data-locker]').forEach(el=>{
      const n=parseInt(el.dataset.locker,10);
      const unlocked = doneCount >= n*2 || (n===6 && doneCount>=9);
      el.style.opacity = unlocked ? '1' : '0.55';
      el.style.borderStyle = unlocked ? 'solid' : 'dashed';
      el.style.borderColor = unlocked ? 'rgb(16 185 129)' : '';
      el.style.background = unlocked ? 'rgb(236 253 245)' : '';
      if(unlocked) el.classList.add('pulse-glow');
    });
    // check victory
    if(doneCount===12){
      const vic=document.getElementById('victory-screen');
      if(vic && vic.classList.contains('hidden')){
        vic.classList.remove('hidden');
        document.getElementById('victory-time').textContent = speedrunOn ? document.getElementById('speedrun-time').textContent : Math.round((Date.now()-state.start)/1000/60)+' min';
        confettiBurst();
        try{ toast('🏆 LEGEND! All 12 missions cleared. Both CVEs found. You’re officially terrifying (in a good way).'); }catch(e){}
      }
    }
    renderBoard();
  }

  function confettiBurst(){
    const layer=document.getElementById('confetti-layer');
    if(!layer) return;
    layer.classList.remove('hidden'); layer.innerHTML='';
    const colors=['#f59e0b','#10b981','#6366f1','#ec4899','#06b6d4','#eab308'];
    for(let i=0;i<40;i++){
      const d=document.createElement('div');
      d.style.position='absolute';
      d.style.left=(Math.random()*100)+'%';
      d.style.top='-10px';
      d.style.width='8px'; d.style.height='8px';
      d.style.background=colors[i%colors.length];
      d.style.borderRadius=Math.random()>0.5?'50%':'2px';
      d.style.animation='confetti '+(1.2+Math.random()*1.2)+'s cubic-bezier(0.25,1,0.5,1) forwards';
      d.style.animationDelay=(Math.random()*0.5)+'s';
      d.style.transform='rotate('+(Math.random()*360)+'deg)';
      layer.appendChild(d);
    }
    setTimeout(()=> layer.classList.add('hidden'), 3000);
  }
  function gainXP(amount){
    state.xp += amount;
    const before=levelFor(state.xp-amount).lvl, after=levelFor(state.xp).lvl;
    if(after>before){ confettiBurst(); try{ toast('⬆️ LEVEL UP! You are now '+levelFor(state.xp).name+'! +'+amount+' XP'); }catch(e){} }
    save(); updateXP();
  }

  function renderBoard(){
    const grid=document.getElementById('mission-grid');
    if(!grid) return;
    grid.innerHTML='';
    MISSIONS.forEach((m,idx)=>{
      const done=!!state.done[m.n];
      const prevDone = m.n===1 ? true : !!state.done[m.n-1];
      const locked = !prevDone && !done;
      const ready = !locked && !done;
      // alternating layout
      const isLeft = idx%2===0;
      const row=document.createElement('div');
      row.className='relative flex items-stretch gap-3 sm:gap-4 '+(isLeft ? 'sm:flex-row' : 'sm:flex-row-reverse');
      // dot
      const dot=document.createElement('div');
      dot.className='absolute left-[10px] sm:left-1/2 sm:-translate-x-1/2 top-6 z-[1] grid h-7 w-7 place-items-center rounded-full border-2 bg-white text-xs font-bold shadow-sm dark:bg-slate-900 '+(done?'border-emerald-500 bg-emerald-500 text-white': locked? 'border-slate-300 text-slate-400':'border-indigo-500 text-indigo-600 pulse-glow');
      dot.textContent= done ? '✓' : locked ? '🔒' : m.n;
      // card
      const card=document.createElement('button');
      card.type='button';
      const bossClass = (m.n===7||m.n===8) ? 'border-2 '+(m.n===7?'border-rose-300 dark:border-rose-500/40':'border-indigo-300 dark:border-indigo-500/40') : 'border border-slate-200 dark:border-slate-800';
      card.className='game-card flex-1 text-left rounded-2xl bg-white p-4 shadow-sm dark:bg-slate-900 '+bossClass+' '+(locked?'mission-locked':'')+' '+(done?'mission-done':'')+' '+(ready?'hover:border-indigo-300':'');
      if(m.n===7||m.n===8) card.classList.add('boss-pulse');
      card.innerHTML=`
        <div class="flex items-start justify-between gap-2">
          <div class="flex gap-3">
            <div class="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-gradient-to-br ${m.color} text-lg text-white shadow-sm">${m.icon}</div>
            <div>
              <p class="mono text-[10px] font-bold tracking-[0.12em] ${done?'text-emerald-600': locked?'text-slate-400':'text-indigo-600'}">${done?'✓ DONE': locked?'LOCKED':'READY'} · MISSION ${String(m.n).padStart(2,'0')} · ${m.xp} XP</p>
              <p class="game-font text-sm font-bold leading-tight text-slate-900 dark:text-white">${m.title} ${m.n===7||m.n===8?'<span class="rounded-full bg-rose-600 px-1.5 py-0.5 text-[10px] text-white">BOSS</span>':''}</p>
              <p class="mono text-xs text-slate-500">${m.subtitle}</p>
            </div>
          </div>
          <span class="mono hidden rounded-full ${done?'bg-emerald-500 text-white':'bg-slate-900 text-white dark:bg-white dark:text-slate-900'} px-2.5 py-1 text-[10px] font-bold sm:inline">${m.diff}</span>
        </div>
        <div class="mt-3 flex flex-wrap gap-1.5">
          <span class="mono rounded-full ${done?'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20':'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'} px-2.5 py-1 text-[11px] font-bold">${done?'Claimed '+m.badge: locked?'Complete M'+(m.n-1)+' to unlock':'Click to play →'}</span>
          ${done?'<span class="mono rounded-full bg-amber-100 px-2.5 py-1 text-[11px] font-bold text-amber-800 dark:bg-amber-500/15">+'+m.xp+' XP earned</span>':''}
        </div>
      `;
      if(!locked) card.addEventListener('click', ()=> openMission(m.n));
      else card.addEventListener('click', ()=> { try{ toast('🔒 Finish Mission '+(m.n-1)+' first — bosses need prep!'); }catch(e){} card.classList.add('shake'); setTimeout(()=>card.classList.remove('shake'),400); });

      const spacer=document.createElement('div');
      spacer.className='hidden flex-1 sm:block';

      if(isLeft){ row.appendChild(card); row.appendChild(spacer); }
      else { row.appendChild(spacer); row.appendChild(card); }
      row.appendChild(dot);
      grid.appendChild(row);
    });
  }

  function openMission(n){
    current=n;
    const m=MISSIONS.find(x=>x.n===n);
    if(!m) return;
    const drawer=document.getElementById('mission-drawer');
    drawer.classList.remove('hidden');
    document.getElementById('drawer-icon').textContent=m.icon;
    document.getElementById('drawer-icon').className='grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-gradient-to-br '+m.color+' text-lg text-white shadow-sm';
    document.getElementById('drawer-num').textContent='MISSION '+String(m.n).padStart(2,'0');
    document.getElementById('drawer-xp').textContent=m.xp+' XP';
    document.getElementById('drawer-diff').textContent=m.diff;
    document.getElementById('drawer-title').textContent=m.title;
    document.getElementById('drawer-subtitle').textContent=m.subtitle;
    document.getElementById('drawer-sage').textContent=m.sage;
    document.getElementById('drawer-brief').innerHTML=m.brief;
    document.getElementById('drawer-objective').innerHTML=m.objective.map(o=>'<li>'+o+'</li>').join('');
    // commands
    const cmdWrap=document.getElementById('drawer-commands');
    cmdWrap.innerHTML='';
    m.commands.forEach(c=>{
      const b=document.createElement('button');
      b.type='button';
      b.className='mono rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200';
      b.innerHTML='▶ '+c.label+' <span class="ml-1 hidden font-normal text-slate-400 sm:inline">· '+c.expect+'</span>';
      b.addEventListener('click', ()=>{
        const term=document.getElementById('drawer-terminal');
        termPrint(term, '$ '+c.cmd+'\n…running…');
        try{ c.run(term); }catch(e){ termPrint(term, 'Error: '+e.message); }
      });
      cmdWrap.appendChild(b);
    });
    // terminal reset
    document.getElementById('drawer-terminal').innerHTML='Click a command above to run it. Your output appears here like a real terminal. ↓\n\n<span class="text-white/40">Hint: '+m.commands[0].expect+'</span>';
    document.getElementById('drawer-input').value='';
    // quiz
    const q=m.quiz;
    const quizEl=document.getElementById('drawer-quiz');
    quizEl.innerHTML=`
      <p class="text-sm font-bold text-slate-900 dark:text-white">🧠 Quick check — no stress, infinite tries:</p>
      <p class="mono mt-2 text-sm leading-relaxed text-slate-700 dark:text-slate-300">${q.q}</p>
      <div class="mt-3 space-y-2" id="quiz-opts">
        ${q.opts.map((o,i)=>`<button type="button" data-quiz="${i}" class="quiz-opt w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-left text-sm hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:hover:bg-slate-700/50">${String.fromCharCode(65+i)}. ${o}</button>`).join('')}
      </div>
      <p id="quiz-feedback" class="mono mt-3 hidden rounded-xl px-3 py-2 text-xs leading-relaxed"></p>
    `;
    // badge
    document.getElementById('drawer-badge').textContent=m.badge.split(' ')[0];
    document.getElementById('drawer-badge-name').textContent=m.badgeName;
    document.getElementById('drawer-badge-xp').textContent='+'+m.xp+' XP';
    document.getElementById('drawer-badge-desc').textContent= state.done[m.n] ? 'Already claimed — replay for fun!' : 'Complete the quiz + run one command to unlock.';
    // quiz handlers
    const doneAlready=!!state.done[m.n];
    quizEl.querySelectorAll('.quiz-opt').forEach(btn=>{
      if(state.quizOk[m.n]!==undefined){
        // restore previous selection styling
        if(parseInt(btn.dataset.quiz,10)===state.quizOk[m.n]) btn.classList.add('!border-emerald-400','!bg-emerald-50');
      }
      btn.addEventListener('click', ()=>{
        const pick=parseInt(btn.dataset.quiz,10);
        const fb=document.getElementById('quiz-feedback');
        fb.classList.remove('hidden');
        if(pick===q.a){
          fb.className='mono mt-3 rounded-xl bg-emerald-50 px-3 py-2 text-xs leading-relaxed text-emerald-800 dark:bg-emerald-500/10 dark:text-emerald-200';
          fb.textContent='✅ '+q.ok;
          state.quizOk[m.n]=pick; save();
          btn.classList.add('!border-emerald-400','!bg-emerald-50');
          try{ toast('🧠 Correct! Now run a command and claim your loot.'); }catch(e){}
        } else {
          fb.className='mono mt-3 rounded-xl bg-amber-50 px-3 py-2 text-xs leading-relaxed text-amber-900 dark:bg-amber-500/10 dark:text-amber-200';
          fb.textContent='💡 '+q.bad[pick] + ' — try again!';
          btn.classList.add('shake');
          setTimeout(()=>btn.classList.remove('shake'),400);
        }
        updateClaim();
      });
    });
    if(state.quizOk[m.n]===q.a){
      const fb=document.getElementById('quiz-feedback');
      fb.classList.remove('hidden');
      fb.className='mono mt-3 rounded-xl bg-emerald-50 px-3 py-2 text-xs leading-relaxed text-emerald-800 dark:bg-emerald-500/10 dark:text-emerald-200';
      fb.textContent='✅ '+q.ok;
    }
    updateClaim();
    // tabs to briefing
    switchDrawerTab('brief');
    drawer.scrollIntoView({behavior:'smooth', block:'start'});
  }
  window.openMission=openMission;
  function closeMission(){
    document.getElementById('mission-drawer').classList.add('hidden');
    current=null;
  }
  window.closeMission=closeMission;

  function switchDrawerTab(name){
    document.querySelectorAll('.drawer-tab').forEach(b=>{
      const on=b.dataset.drawerTab===name;
      b.className= on
        ? 'drawer-tab rounded-full bg-slate-900 px-3 py-1.5 text-xs font-bold text-white'
        : 'drawer-tab rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300';
    });
    document.querySelectorAll('[data-drawer-panel]').forEach(p=>{
      p.classList.toggle('hidden', p.dataset.drawerPanel!==name);
    });
  }
  document.querySelectorAll('.drawer-tab').forEach(b=> b.addEventListener('click', ()=> switchDrawerTab(b.dataset.drawerTab)));

  function updateClaim(){
    if(current===null) return;
    const m=MISSIONS.find(x=>x.n===current);
    const quizOk = state.quizOk[current]===m.quiz.a;
    const cmdOk = !!state.cmdOk[current];
    const done = !!state.done[current];
    const btn=document.getElementById('drawer-claim');
    if(done){
      btn.textContent='✅ Already claimed — '+m.badge+' earned!';
      btn.disabled=true;
      btn.className='mt-3 w-full rounded-full bg-emerald-500 px-4 py-2.5 text-sm font-bold text-white';
      return;
    }
    if(quizOk && cmdOk){
      btn.textContent='🎉 Claim loot: '+m.badge+' +'+m.xp+' XP';
      btn.disabled=false;
      btn.className='mt-3 w-full rounded-full bg-gradient-to-r from-amber-400 to-orange-500 px-4 py-2.5 text-sm font-bold text-amber-950 shadow-md hover:from-amber-300 hover:to-orange-400 badge-pop';
    } else {
      const need=[];
      if(!quizOk) need.push('answer quiz');
      if(!cmdOk) need.push('run a command');
      btn.textContent='🔒 '+need.join(' + ')+' to unlock';
      btn.disabled=true;
      btn.className='mt-3 w-full rounded-full border border-slate-200 bg-slate-100 px-4 py-2.5 text-sm font-bold text-slate-400 dark:border-slate-700 dark:bg-slate-800';
    }
  }
  function claimMission(){
    if(current===null) return;
    const m=MISSIONS.find(x=>x.n===current);
    if(!m || state.done[current]) return;
    const quizOk = state.quizOk[current]===m.quiz.a;
    const cmdOk = !!state.cmdOk[current];
    if(!quizOk || !cmdOk) return;
    state.done[current]=true;
    state.streak=(state.streak||0)+1;
    gainXP(m.xp);
    save(); updateXP(); updateClaim();
    confettiBurst();
    try{ toast('🎉 Mission '+current+' cleared! '+m.badge+' unlocked +'+m.xp+' XP. Streak x'+state.streak); }catch(e){}
  }
  window.claimMission=claimMission;

  function runCustomCommand(){
    const input=document.getElementById('drawer-input');
    const term=document.getElementById('drawer-terminal');
    const val=input.value.trim();
    if(!val) return;
    termPrint(term, '$ '+val);
    if(/healthz/i.test(val)) fetch('/healthz').then(r=>r.text().then(t=> termPrint(term, t.slice(0,900))));
    else if(/curl.*\//.test(val)) fetch('/').then(r=>r.text().then(t=> termPrint(term, t.slice(0,900))));
    else if(/nmap|masscan/i.test(val)) termPrint(term, '💡 Nice hax0r vibe, but try the green buttons above — they’re wired to the real container.');
    else termPrint(term, 'Command “'+val+'” noted. Try the preset buttons — they show what matters for this mission.');
    input.value='';
    if(current!==null){ state.cmdOk[current]=true; save(); updateClaim(); }
  }
  window.runCustomCommand=runCustomCommand;
  document.getElementById('drawer-input')?.addEventListener('keydown', e=>{ if(e.key==='Enter') runCustomCommand(); });

  // live dot
  fetch('/healthz').then(r=> r.ok ? r.text() : Promise.reject()).then(()=> {
    const d=document.getElementById('game-live-dot');
    if(d) d.textContent='● LIVE — 8.4.26 vulnerable';
    if(d) d.className='font-mono font-bold text-emerald-400';
  }).catch(()=>{
    const d=document.getElementById('game-live-dot');
    if(d) d.textContent='○ checking… (open :8080)';
    if(d) d.className='font-mono font-bold text-amber-300';
  });

  // speedrun
  document.getElementById('speedrun-toggle')?.addEventListener('click', function(){
    speedrunOn=!speedrunOn;
    this.textContent = speedrunOn ? '⏱ ON' : '⏱ OFF';
    this.className = speedrunOn ? 'rounded-full bg-indigo-600 px-3 py-1 text-[11px] font-bold text-white' : 'rounded-full border border-slate-200 bg-white px-3 py-1 text-[11px] font-bold text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300';
    document.getElementById('speedrun-time').classList.toggle('hidden', !speedrunOn);
    if(speedrunOn){
      const start=Date.now();
      speedrunTimer=setInterval(()=>{
        const s=Math.floor((Date.now()-start)/1000);
        const mm=String(Math.floor(s/60)).padStart(2,'0'), ss=String(s%60).padStart(2,'0');
        document.getElementById('speedrun-time').textContent=mm+':'+ss;
      },1000);
    } else { clearInterval(speedrunTimer); }
  });

  // hint
  window.gameHintBoard=function(){
    const done=Object.keys(state.done).length;
    const next=MISSIONS.find(m=> !state.done[m.n]);
    if(!next) { try{ toast('🎉 All missions done — go flex your victory code!'); }catch(e){} return; }
    openMission(next.n);
    try{ toast('💡 Hint: '+ next.title +' — check Sage’s whisper and the Hack Lab buttons.'); }catch(e){}
  };

  // reset
  window.gameReset=function(){
    if(!confirm('Reset all progress, XP, and badges?')) return;
    state={xp:0, done:{}, avatar:state.avatar, quizOk:{}, cmdOk:{}, streak:0, start:Date.now()};
    save(); updateXP();
    try{ toast('Progress reset — fresh run!'); }catch(e){}
    document.getElementById('victory-screen')?.classList.add('hidden');
    closeMission();
  };

  window.shareVictory=function(){
    const code='NIMBUS-LEGEND-'+ btoa(state.avatar + '|' + state.xp + '|' + Object.keys(state.done).length + '|'+ new Date().toISOString().slice(0,10)).slice(0,16).toUpperCase();
    navigator.clipboard.writeText(code).then(()=> { try{ toast('📋 Victory code copied: '+code); }catch(e){} }).catch(()=> prompt('Your victory code:', code));
  };

  // memory mini-game
  window.playMemoryGame=function(){
    const g=document.getElementById('memory-game');
    g.classList.toggle('hidden');
  };
  (function(){
    let pct=0, hold=null;
    const bar=document.getElementById('memory-bar'), msg=document.getElementById('memory-msg'), btn=document.getElementById('memory-hold');
    if(!btn) return;
    function tick(){
      pct=Math.min(100, pct+2+Math.random()*3);
      bar.style.width=pct+'%';
      if(pct<40) msg.textContent='Allocating… '+Math.round(pct)+'% — still safe';
      else if(pct<80) msg.textContent='Memory climbing… '+Math.round(pct)+'% — getting warm';
      else if(pct<100) msg.textContent='Almost at memory_limit 256M… '+Math.round(pct)+'%';
      else {
        msg.textContent='💥 OOM! longjmp! PHP says “Allowed memory size exhausted” — but BOTH 8.4.26 and 8.4.27 do this. So 500 ≠ hack. That’s the lesson!';
        bar.className='h-full w-full rounded-full bg-rose-500';
        try{ toast('💥 Boom — that’s the Memory Leviathan’s trick. Same 500 on patched!'); }catch(e){}
        clearInterval(hold); hold=null; pct=0;
        setTimeout(()=>{ bar.style.width='0%'; bar.className='h-full w-0 rounded-full bg-gradient-to-r from-emerald-400 to-amber-400 transition-all duration-150'; msg.textContent='Press and hold again to replay.'; },2000);
      }
    }
    btn.addEventListener('pointerdown', ()=>{ if(hold) return; hold=setInterval(tick, 80); });
    btn.addEventListener('pointerup', ()=>{ if(hold){ clearInterval(hold); hold=null; if(pct<100) msg.textContent='Released at '+Math.round(pct)+'% — hold all the way for OOM!'; }});
    btn.addEventListener('pointerleave', ()=>{ if(hold){ clearInterval(hold); hold=null; }});
  })();

  // ghost mini-game
  window.playGhostGame=function(){
    const g=document.getElementById('ghost-game');
    g.classList.toggle('hidden');
    if(!g.classList.contains('hidden')) genGhost();
  };
  function genGhost(){
    const wrap=document.getElementById('ghost-pids'), msg=document.getElementById('ghost-msg');
    if(!wrap) return;
    wrap.innerHTML='';
    const pids=[12,13,14,15,16,17,18,19,20];
    const ghost=pids[Math.floor(Math.random()*pids.length)];
    const arr=[];
    for(let i=0;i<8;i++) arr.push(pids[Math.floor(Math.random()*pids.length)]);
    arr.splice(Math.floor(Math.random()*7),0,ghost);
    arr.push(ghost);
    // shuffle a bit: ensure ghost appears twice
    for(let i=0;i<10;i++){
      const btn=document.createElement('button');
      btn.type='button';
      btn.className='rounded-xl border border-white/20 bg-white/10 px-2 py-2 text-xs font-mono font-bold text-white hover:bg-white/20';
      btn.textContent='PID '+arr[i%arr.length];
      if(arr[i%arr.length]===ghost) btn.dataset.ghost='1';
      btn.addEventListener('click', ()=>{
        if(btn.dataset.ghost){
          msg.textContent='✅ Got it! Ghost PID '+ghost+' appeared twice — same worker = haunted. That’s CVE-2026-109619.';
          btn.className='rounded-xl bg-emerald-400 px-2 py-2 text-xs font-mono font-bold text-emerald-900';
          try{ toast('👻 Ghost caught! Same PID = same worker = exposure.'); }catch(e){}
        } else {
          msg.textContent='❌ Nope — that PID only showed once. The ghost repeats. Try again!';
          btn.classList.add('shake');
          setTimeout(()=>btn.classList.remove('shake'),400);
        }
      });
      wrap.appendChild(btn);
    }
    msg.textContent='Click the PID that appears twice — that’s the ghost worker.';
  }

  // keyboard shortcuts 1-9
  document.addEventListener('keydown', (e)=>{
    if(e.target.tagName==='INPUT') return;
    const n=parseInt(e.key,10);
    if(n>=1 && n<=9){
      const m=MISSIONS.find(x=>x.n===n);
      if(m && (m.n===1 || state.done[m.n-1] || state.done[m.n])) openMission(n);
    }
  });
  // konami
  const konami=['ArrowUp','ArrowUp','ArrowDown','ArrowDown','ArrowLeft','ArrowRight','ArrowLeft','ArrowRight','b','a'];
  let kpos=0;
  document.addEventListener('keydown', (e)=>{
    if(e.key===konami[kpos]){ kpos++; if(kpos===konami.length){ kpos=0; confettiBurst(); try{ toast('🎮 KONAMI CODE! You unlocked “+100 XP CHEAT” — jk, but have confetti!'); }catch(e){} gainXP(50); }}
    else kpos=0;
  });

  // init
  setAvatar(state.avatar);
  updateXP();
})();
</script>
</div>

      <!-- ══ CVE-2026-109618 panel ══ -->
      <div data-lab-panel="cve618" class="hidden space-y-4">
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">CVE-2026-109618 · RCE via OOM corruption</h3>
            <span class="rounded-full bg-rose-600 px-2 py-0.5 text-[11px] font-bold text-white">CVSS 4.0 9.2</span>
            <span class="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-mono text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">FPM SAPI · pre-auth</span>
          </div>
          <table class="mt-3 w-full text-left text-xs">
            <tr class="border-b border-slate-100 dark:border-slate-800"><th class="py-2 font-semibold text-slate-500">Affected</th><td class="py-2 font-mono">PHP 8.4 &lt; 8.4.27, 8.5 &lt; 8.5.12, 8.3 &lt; 8.3.36, 8.2 &lt; 8.2.35</td></tr>
            <tr class="border-b border-slate-100 dark:border-slate-800"><th class="py-2 font-semibold text-slate-500">Fixed in</th><td class="py-2 font-mono">8.4.27 / 8.5.12 / 8.3.36 / 8.2.35</td></tr>
            <tr><th class="py-2 font-semibold text-slate-500">Where</th><td class="py-2">PHP engine — request memory handling after <code class="font-mono">longjmp</code> on OOM</td></tr>
          </table>
          <div class="mt-4 rounded-xl border border-indigo-200 bg-indigo-50 p-4 dark:border-indigo-500/20 dark:bg-indigo-500/10">
            <p class="text-xs font-bold text-indigo-900 dark:text-indigo-200">How to find it in the lab</p>
            <ol class="mt-2 list-decimal space-y-1.5 pl-5 text-xs leading-relaxed text-indigo-900/80 dark:text-indigo-200/80">
              <li>Read <code class="font-mono">cve-demonstrations/CVE-2026-109618.md</code> in the repo — evidence worksheet is there.</li>
              <li>Build a diagnostic image with symbols / ASAN for that PHP revision (the release image has no sanitizer). Keep the exact source revision.</li>
              <li>Use the vendor’s regression test as trigger (bound memory + timeout). The lab intentionally has <strong>no</strong> arbitrary memory-exhaustion endpoint — you add the minimal trigger yourself.</li>
              <li>Observe: PHP’s normal <code class="font-mono">Allowed memory size exhausted</code> is expected. What proves this bug is a sanitizer trace of <em>uninitialized memory use</em> on the engine’s allocation/cleanup path tied to that revision, not the error string.</li>
              <li>Record request, error output, worker PID, exit status, and full trace. Distinguish PHP <code class="font-mono">memory_limit 256M</code> (this image) from container OOM-killer (<code class="font-mono">docker inspect</code>).</li>
              <li>Repeat identical request against the patched image — trace should vanish.</li>
            </ol>
          </div>
          <div class="mt-3 rounded-xl bg-slate-950 p-4 font-mono text-xs text-slate-200">
            <p class="text-slate-400"># Example — lab health check (same config you must use for the comparison)</p>
            <p>curl -s http://127.0.0.1:8080/index.php?api=ping | jq .php,.sapi</p>
            <p class="mt-2 text-slate-400"># Capture both runtimes for your write-up</p>
            <p>docker inspect php2shell-vm --format '{{.Image}} {{.Config.Image}}' &gt; evidence/8.4.26-digest.txt</p>
            <p>docker inspect php2shell-patched --format '{{.Image}}' &gt; evidence/8.4.27-digest.txt</p>
          </div>
          <p class="mt-2 text-[11px] text-slate-400">A crash, 500, or OOM-killed container alone does <strong>not</strong> prove memory corruption or RCE.</p>
        </div>
      </div>

      <!-- ══ CVE-2026-109619 panel ══ -->
      <div data-lab-panel="cve619" class="hidden space-y-4">
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">CVE-2026-109619 · RCE via stale global state</h3>
            <span class="rounded-full bg-rose-600 px-2 py-0.5 text-[11px] font-bold text-white">CVSS 4.0 9.2</span>
            <span class="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-mono text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">FPM reuse · pre-auth</span>
          </div>
          <table class="mt-3 w-full text-left text-xs">
            <tr class="border-b border-slate-100 dark:border-slate-800"><th class="py-2 font-semibold text-slate-500">Affected</th><td class="py-2 font-mono">PHP 8.4 &lt; 8.4.27, 8.5 &lt; 8.5.12, 8.3 &lt; 8.3.36, 8.2 &lt; 8.2.35</td></tr>
            <tr class="border-b border-slate-100 dark:border-slate-800"><th class="py-2 font-semibold text-slate-500">Fixed in</th><td class="py-2 font-mono">8.4.27 / 8.5.12 / 8.3.36 / 8.2.35</td></tr>
            <tr><th class="py-2 font-semibold text-slate-500">Where</th><td class="py-2">PHP engine — global still points at freed per-request memory → later request on same worker reuses it</td></tr>
          </table>
          <div class="mt-4 rounded-xl border border-rose-200 bg-rose-50 p-4 dark:border-rose-500/20 dark:bg-rose-500/10">
            <p class="text-xs font-bold text-rose-900 dark:text-rose-200">How to find it in the lab</p>
            <ol class="mt-2 list-decimal space-y-1.5 pl-5 text-xs leading-relaxed text-rose-900/80 dark:text-rose-200/80">
              <li>Read <code class="font-mono">cve-demonstrations/CVE-2026-109619.md</code>. Identify the affected global and its init/shutdown paths in the verified patch.</li>
              <li>Build a diagnostic image and pin <strong>one FPM worker</strong>: <code class="font-mono">pm=static, pm.max_children=1, pm.max_requests=0</code>. Stop dashboard polling (it steals the worker) while you test.</li>
              <li>Record the worker PID per request — the bundled <code class="font-mono">?api=ping&amp;showpid=1</code> returns it as <code class="font-mono">pid</code> (opt-in, added for this exercise). You can also add <code class="font-mono">getmypid()</code> to your own instrumentation.</li>
              <li>Send vendor’s request A (put freed object into the global) then request B (trigger dereference). Confirm both hit the <em>same PID</em>. Capture the lifetime-violation trace; repeat with a fresh worker as control.</li>
              <li>Persisting session data, caches, or matching response text alone are <strong>not</strong> proof of stale freed memory.</li>
              <li>Repeat identical pair against the patched image — violation must be gone.</li>
            </ol>
          </div>
          <div class="mt-3 rounded-xl bg-slate-950 p-4 font-mono text-xs text-slate-200">
            <p class="text-slate-400"># Pin worker + observe PIDs (adjust pool conf in your diagnostic Dockerfile)</p>
            <p>curl -s 'http://127.0.0.1:8080/index.php?api=ping&showpid=1'</p>
            <p>docker exec php2shell-vm tail -f /var/log/nginx/access.log   # rt + urt</p>
            <p>docker exec php2shell-vm ps -ef | grep '[p]hp-fpm'          # fpm children</p>
          </div>
          <p class="mt-2 text-[11px] text-slate-400">Do not use real credentials as markers — use synthetic canaries. A memory disclosure alone does not equal RCE.</p>
        </div>
      </div>

      <!-- ══ Verify panel ══ -->
      <div data-lab-panel="verify" class="hidden space-y-4">
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-bold text-slate-900 dark:text-white">Verify you’re testing the right thing</h3>
          <div class="mt-3 grid gap-3 sm:grid-cols-2">
            <div class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 dark:border-slate-700 dark:bg-slate-800/60">
              <p class="text-xs font-semibold text-slate-700 dark:text-slate-200">Full-stack healthcheck</p>
              <code class="mt-1 block rounded bg-white px-2 py-1.5 font-mono text-xs dark:bg-slate-900">curl -s http://127.0.0.1:8080/index.php?api=ping</code>
              <p class="mt-1 text-xs text-slate-500">Want: <code class="font-mono">{"status":"ok","php":"8.4.26","sapi":"fpm-fcgi"}</code> · Fail means nginx or FPM is down; check <code class="font-mono">docker logs php2shell-vm</code>.</p>
            </div>
            <div class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 dark:border-slate-700 dark:bg-slate-800/60">
              <p class="text-xs font-semibold text-slate-700 dark:text-slate-200">Liveness (no PHP)</p>
              <code class="mt-1 block rounded bg-white px-2 py-1.5 font-mono text-xs dark:bg-slate-900">curl -s http://127.0.0.1:8080/healthz</code>
              <p class="mt-1 text-xs text-slate-500">Want: <code class="font-mono">ok</code> from nginx. If this works but <code class="font-mono">api=ping</code> fails, FPM pool is broken.</p>
            </div>
            <div class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 dark:border-slate-700 dark:bg-slate-800/60">
              <p class="text-xs font-semibold text-slate-700 dark:text-slate-200">Inside the container</p>
              <code class="mt-1 block rounded bg-white px-2 py-1.5 font-mono text-xs dark:bg-slate-900">docker exec php2shell-vm php -v<br/>docker exec php2shell-vm supervisorctl status</code>
              <p class="mt-1 text-xs text-slate-500">Both <code class="font-mono">nginx</code> and <code class="font-mono">php-fpm</code> must be <code class="font-mono">RUNNING</code>.</p>
            </div>
            <div class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 dark:border-slate-700 dark:bg-slate-800/60">
              <p class="text-xs font-semibold text-slate-700 dark:text-slate-200">Evidence collector</p>
              <code class="mt-1 block rounded bg-white px-2 py-1.5 font-mono text-xs dark:bg-slate-900">python3 cve-demonstrations/collect_runtime.py --port 8080 &gt; baseline.json</code>
              <p class="mt-1 text-xs text-slate-500">Loopback-only, disables proxies, caps response. Keeps <code class="font-mono">image digest + config + request + worker PID + trace</code> together.</p>
            </div>
          </div>
          <div class="mt-4 overflow-x-auto">
            <table class="w-full text-left text-xs">
              <thead class="text-[11px] uppercase tracking-wider text-slate-400"><tr><th class="py-2">Check</th><th class="py-2">This lab (vulnerable)</th><th class="py-2">Patched comparison</th></tr></thead>
              <tbody class="divide-y divide-slate-100 dark:divide-slate-800/60">
                <tr><td class="py-2 font-medium">PHP image</td><td class="py-2 font-mono">php:8.4.26-fpm-alpine (digest …)</td><td class="py-2 font-mono">php:8.4.27 / 8.5.12 / 8.3.36 / 8.2.35</td></tr>
                <tr><td class="py-2 font-medium">SAPI must be</td><td class="py-2 font-mono" colspan="2">fpm-fcgi — CLI alone does not exercise same lifecycle</td></tr>
                <tr><td class="py-2 font-medium">CVE-2026-109618 signal</td><td class="py-2">Sanitizer trace of uninitialized use after OOM <code class="font-mono">longjmp</code></td><td class="py-2 text-emerald-600">Trace gone</td></tr>
                <tr><td class="py-2 font-medium">CVE-2026-109619 signal</td><td class="py-2">Same-worker cross-request UAF trace on that global</td><td class="py-2 text-emerald-600">Trace gone, fresh-worker control clean</td></tr>
                <tr><td class="py-2 font-medium">Not evidence</td><td class="py-2" colspan="2"><code class="font-mono">Allowed memory size exhausted</code> · OOM-killed container · 500 · session persistence alone · matching response text</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="rounded-2xl border border-amber-400/40 bg-amber-50 p-4 text-xs leading-relaxed text-amber-900 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-200">
          <strong>Tear down &amp; harden:</strong> <code class="rounded bg-white px-1 py-0.5 font-mono dark:bg-slate-800">docker rm -f php2shell-vm</code> when done. To fix the engine, upgrade PHP to ≥ patched versions and keep the same nginx/FPM topology — then rerun <em>your exact</em> workbook steps and confirm the traces no longer reproduce.
        </div>
      </div>
      <!-- ══ Real-world hunt panel (tester step-by-step guide) ══ -->
      <div data-lab-panel="field" class="hidden space-y-4">
        <div class="rounded-2xl border border-indigo-200 bg-white p-5 shadow-sm dark:border-indigo-500/20 dark:bg-slate-900">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">Tester field guide — finding PHP2Shell in the real world</h3>
            <span class="rounded-full bg-indigo-600 px-2 py-0.5 text-[11px] font-bold text-white">10 STEPS</span>
            <span class="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 font-mono text-[11px] text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">no exploit payload</span>
          </div>
          <p class="mt-2 text-xs leading-relaxed text-slate-600 dark:text-slate-400">A version string is a <strong>lead</strong>, not a finding. A defensible finding has four parts: <strong>asset + exact build</strong>, <strong>patch status</strong> (including vendor backports), <strong>reachability</strong> (SAPI + advisory attack requirements), and an honest <strong>evidence tier</strong>. Work the ten steps below in order; each one produces a piece of evidence you can paste into a ticket.</p>
          <div class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <div class="rounded-xl bg-indigo-50 p-2 dark:bg-indigo-500/10"><p class="text-[10px] font-bold text-indigo-900 dark:text-indigo-200 leading-tight">1 · Ground truth</p></div>
            <div class="rounded-xl bg-indigo-50 p-2 dark:bg-indigo-500/10"><p class="text-[10px] font-bold text-indigo-900 dark:text-indigo-200 leading-tight">2 · Inventory</p></div>
            <div class="rounded-xl bg-indigo-50 p-2 dark:bg-indigo-500/10"><p class="text-[10px] font-bold text-indigo-900 dark:text-indigo-200 leading-tight">3 · Fingerprint</p></div>
            <div class="rounded-xl bg-amber-50 p-2 dark:bg-amber-500/10"><p class="text-[10px] font-bold text-amber-900 dark:text-amber-200 leading-tight">4 · Patch status</p></div>
            <div class="rounded-xl bg-amber-50 p-2 dark:bg-amber-500/10"><p class="text-[10px] font-bold text-amber-900 dark:text-amber-200 leading-tight">5 · Attack requirements</p></div>
            <div class="rounded-xl bg-amber-50 p-2 dark:bg-amber-500/10"><p class="text-[10px] font-bold text-amber-900 dark:text-amber-200 leading-tight">6 · Safe reproduction</p></div>
            <div class="rounded-xl bg-emerald-50 p-2 dark:bg-emerald-500/10"><p class="text-[10px] font-bold text-emerald-900 dark:text-emerald-200 leading-tight">7 · Evidence ladder</p></div>
            <div class="rounded-xl bg-emerald-50 p-2 dark:bg-emerald-500/10"><p class="text-[10px] font-bold text-emerald-900 dark:text-emerald-200 leading-tight">8 · Log hunt</p></div>
            <div class="rounded-xl bg-emerald-50 p-2 dark:bg-emerald-500/10"><p class="text-[10px] font-bold text-emerald-900 dark:text-emerald-200 leading-tight">9 · Report</p></div>
            <div class="rounded-xl bg-emerald-50 p-2 dark:bg-emerald-500/10"><p class="text-[10px] font-bold text-emerald-900 dark:text-emerald-200 leading-tight">10 · Retest</p></div>
          </div>
          <p class="mt-2 text-[11px] leading-relaxed text-slate-600 dark:text-slate-400">Each step pairs <strong>"in the real world"</strong> with a matching <strong>lab exercise</strong> in <code class="font-mono text-slate-500 dark:text-slate-300">cve-demonstrations/REAL-WORLD-TESTER-GUIDE.md</code> — no exploit payloads, version-and-config findings only.</p>
          <div class="mt-4 rounded-xl border border-amber-400/50 bg-amber-50 px-4 py-3 text-xs leading-relaxed text-amber-900 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-200"><strong>Rule 0 — authorization.</strong> Only assets you own or have written permission to test. Every command here is passive, read-only local triage, or aimed at the loopback lab. Never run public exploit PoCs on production — these are memory-corruption bugs, so a “harmless check” can crash workers, leak other users' session memory, or take the site down. There is no exploit payload in this guide, and you do not need one to drive a patch.</div>
          <p class="mt-3 text-[11px] text-slate-400">Companion workbook (full commands, exercises and report template): <code class="font-mono text-slate-600 dark:text-slate-300">cve-demonstrations/REAL-WORLD-TESTER-GUIDE.md</code> in the repository. Advisory facts verified 2026-10-25 — re-read primary sources at the start of every engagement.</p>
        </div>

        <!-- ── Phase A ── -->
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-bold text-slate-900 dark:text-white">Phase A — Find the assets <span class="ml-1 font-mono text-xs font-normal text-slate-400">steps 1–3</span></h3>
          <ol class="mt-4 space-y-5 text-xs leading-relaxed text-slate-700 dark:text-slate-300">
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-xs font-bold text-white">1</span><div class="min-w-0 flex-1">
              <p class="font-bold text-slate-900 dark:text-white">Build ground truth from primary sources (before touching a target).</p>
              <p class="mt-1">Read the PHP.net advisory and both GHSAs; write a one-page “detection hypothesis”: fixed builds <code class="font-mono">8.5.12 / 8.4.27 / 8.3.36 / 8.2.35</code>, affected SAPIs (<code class="font-mono">mod_php</code> highest risk; FPM, php-cgi, FrankenPHP, LSAPI also in scope), and the fix strategy in diff keywords: <em>OOM <code class="font-mono">longjmp</code> removal</em> (618) and <em>complete request-state reset at shutdown</em> (619). Note what was <strong>demonstrated</strong> vs <strong>suspected</strong>: PHP validated RCE on <code class="font-mono">mod_php</code>; for FPM it validated the <strong>619 session-lifecycle</strong> path and says <strong>no complete FPM exploit was demonstrated for 618</strong>.</p>
              <div class="mt-2 overflow-x-auto rounded-xl bg-slate-950 p-3 font-mono text-[11px] text-slate-200">
                <p class="text-slate-400"># Primary sources to record in your notes (URLs at the bottom of this tab)</p>
                <p>php.net/archive/2026.php#2026-10-21-5 · GHSA-w8hw-w9fx-j79w · GHSA-6wmf-4rv5-p3rp</p>
                <p>cve.org CVE-2026-109618 / -109619 · CISA alert · NCSC-NL/php2shell</p>
              </div>
              <p class="mt-2 text-[11px] text-slate-500 dark:text-slate-400"><strong>Record:</strong> version ranges, CVSS v4.0 vector <code class="font-mono">AV:N/AC:H/AT:P/...</code> (9.2), EOL source backports for 7.4/8.0/8.1, and the temporary mitigations. <strong>Why:</strong> AC:H + AT:P mean “old version” ≠ “trivially exploitable here”.</p>
            </div></li>
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-xs font-bold text-white">2</span><div class="min-w-0 flex-1">
              <p class="font-bold text-slate-900 dark:text-white">Inventory every PHP runtime you own — not just the public website.</p>
              <p class="mt-1">Work with the asset owner from the inside out: hosts, FPM pools, containers/images, CI build contexts, and appliances/products that embed PHP. Internet-facing web-serving SAPIs come first.</p>
              <div class="mt-2 overflow-x-auto rounded-xl bg-slate-950 p-3 font-mono text-[11px] text-slate-200">
                <p class="text-slate-400"># Host packages (run on hosts you administer)</p>
                <p>rpm -qa | grep -i php ; dpkg -l 'php*' | grep ^ii</p>
                <p class="text-slate-400"># Containers / clusters / build contexts</p>
                <p>docker ps --format '{{.Names}} {{.Image}}' ; docker image ls --digests</p>
                <p>kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{"\n"}{end}{end}'</p>
                <p>grep -RniE 'FROM php:|php[0-9.]*-fpm' .</p>
                <p class="text-slate-400"># Appliances: check vendor advisories + NCSC-NL software/ list</p>
              </div>
              <p class="mt-2 text-[11px] text-slate-500 dark:text-slate-400"><strong>Record:</strong> <code class="font-mono">asset, owner, exposure, php source (package/image/appliance), SAPI, evidence, ticket</code>. <strong>Pitfall:</strong> embedded PHP in appliances needs its own vendor ticket — you cannot just <code class="font-mono">apt upgrade</code> it.</p>
            </div></li>
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-xs font-bold text-white">3</span><div class="min-w-0 flex-1">
              <p class="font-bold text-slate-900 dark:text-white">Fingerprint safely: one ordinary GET/HEAD, then local authoritative checks.</p>
              <div class="mt-2 overflow-x-auto rounded-xl bg-slate-950 p-3 font-mono text-[11px] text-slate-200">
                <p class="text-slate-400"># Remote — passive, no payload</p>
                <p>curl -sSI https://TARGET/ | grep -iE '^(HTTP/|server|x-powered-by|set-cookie)'</p>
                <p class="text-slate-400"># Local — the SAPI that actually serves requests</p>
                <p>php -v ; php -r 'echo PHP_VERSION," ",PHP_SAPI,PHP_EOL;'</p>
                <p>php-fpm -v ; php -i | grep -iE 'Server API|Loaded Configuration File'</p>
                <p class="text-slate-400"># This lab: two independent signals, loopback only</p>
                <p>curl -s 'http://127.0.0.1:8080/index.php?api=ping' | jq .php,.sapi</p>
                <p>python3 cve-demonstrations/collect_runtime.py --port 8080 &gt; baseline.json</p>
              </div>
              <p class="mt-2 text-[11px] text-slate-500 dark:text-slate-400"><strong>Want:</strong> <code class="font-mono">PHP/8.4.26</code> + <code class="font-mono">fpm-fcgi</code>. <strong>Pitfalls:</strong> <code class="font-mono">expose_php=Off</code> hides the header; CLI <code class="font-mono">php -v</code> can be a different build from FPM; a banner is L1 evidence only (step 7).</p>
            </div></li>
          </ol>
        </div>

        <!-- ── Phase B ── -->
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-bold text-slate-900 dark:text-white">Phase B — Qualify the exposure <span class="ml-1 font-mono text-xs font-normal text-slate-400">steps 4–6</span></h3>
          <ol class="mt-4 space-y-5 text-xs leading-relaxed text-slate-700 dark:text-slate-300">
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-amber-500 text-xs font-bold text-white">4</span><div class="min-w-0 flex-1">
              <p class="font-bold text-slate-900 dark:text-white">Establish patch status — check for vendor backports, not just the version number.</p>
              <div class="mt-2 overflow-x-auto rounded-xl bg-slate-950 p-3 font-mono text-[11px] text-slate-200">
                <p class="text-slate-400"># Debian/Ubuntu · RHEL-like · Alpine</p>
                <p>zgrep -iE 'CVE-2026-10961[89]|php2shell' /usr/share/doc/php*/changelog.Debian.gz</p>
                <p>rpm -q --changelog php | grep -iE 'CVE-2026-10961[89]|php2shell'</p>
                <p>apk info -vv | grep -i '^php'</p>
                <p class="text-slate-400"># Pin digests, and compare source releases</p>
                <p>docker image inspect --format '{{index .RepoDigests 0}}' php:8.4.26-fpm-alpine</p>
                <p>git -C php-src log --oneline php-8.4.26..php-8.4.27 -- Zend main ext/session</p>
              </div>
              <div class="mt-2 overflow-x-auto"><table class="w-full text-left text-[11px]"><thead class="uppercase tracking-wider text-slate-400"><tr><th class="py-1.5">Observed</th><th class="py-1.5">Verdict</th></tr></thead><tbody class="divide-y divide-slate-100 dark:divide-slate-800">
                <tr><td class="py-1.5 font-mono">&lt; 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, no backport</td><td class="py-1.5">Vulnerable build → step 5</td></tr>
                <tr><td class="py-1.5">Lower version, but changelog shows backport</td><td class="py-1.5">Patched — attach changelog as evidence</td></tr>
                <tr><td class="py-1.5 font-mono">8.1 / 8.0 / 7.4</td><td class="py-1.5">No upstream binary fix — verify source/LTS backport</td></tr>
                <tr><td class="py-1.5">≥ fixed milestone</td><td class="py-1.5">Patched — still verify workers were restarted</td></tr>
              </tbody></table></div>
              <p class="mt-2 text-[11px] text-slate-500 dark:text-slate-400"><strong>Restart matters:</strong> a patched package with old FPM workers still running is an unpatched process. Check with <code class="font-mono">ps -ef | grep '[p]hp-fpm'</code> (or <code class="font-mono">supervisorctl status</code>).</p>
            </div></li>
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-amber-500 text-xs font-bold text-white">5</span><div class="min-w-0 flex-1">
              <p class="font-bold text-slate-900 dark:text-white">Check the attack requirements — the <code class="font-mono">AT:P</code> in the CVSS vector.</p>
              <p class="mt-1">Read the <strong>effective</strong> INI of the web SAPI, front-door limits, per-request INI overrides, and worker lifecycle. This turns a scanner hit into a real finding.</p>
              <div class="mt-2 overflow-x-auto rounded-xl bg-slate-950 p-3 font-mono text-[11px] text-slate-200">
                <p>php --ini</p>
                <p>php -i | grep -iE 'memory_limit|post_max_size|upload_max_filesize|max_file_uploads|session.upload_progress.enabled|fatal_error_backtraces|log_errors|error_log|error_reporting|max_execution_time'</p>
                <p>php-fpm -tt 2&gt;&amp;1 | grep -iE 'php_admin|php_value|pm.max_requests|catch_workers_output'</p>
                <p>nginx -T 2&gt;/dev/null | grep -iE 'client_max_body_size|fastcgi_pass|PHP_VALUE|PHP_ADMIN_VALUE'</p>
                <p>grep -RniE 'php_(admin_)?value|PHP_(ADMIN_)?VALUE' /etc/nginx /etc/apache2 /etc/httpd 2&gt;/dev/null</p>
                <p>find /var/www -name '.user.ini' -o -name '.htaccess' 2&gt;/dev/null</p>
              </div>
              <div class="mt-2 overflow-x-auto"><table class="w-full text-left text-[11px]"><thead class="uppercase tracking-wider text-slate-400"><tr><th class="py-1.5">Condition</th><th class="py-1.5">Why it matters</th></tr></thead><tbody class="divide-y divide-slate-100 dark:divide-slate-800">
                <tr><td class="py-1.5 font-mono">memory_limit</td><td class="py-1.5">618 needs a controllable OOM; <code class="font-mono">-1</code> is a partial mitigation</td></tr>
                <tr><td class="py-1.5 font-mono">post_max_size, multipart</td><td class="py-1.5">OOM strategies abuse part headers, nesting, empty file controls</td></tr>
                <tr><td class="py-1.5 font-mono">session.upload_progress.enabled=1</td><td class="py-1.5">confirmed early producer/consumer for 619; no <code class="font-mono">session_start()</code> needed</td></tr>
                <tr><td class="py-1.5 font-mono">fatal_error_backtraces=1</td><td class="py-1.5">PHP 8.5 confirmed producer of stale backtrace state</td></tr>
                <tr><td class="py-1.5 font-mono">PHP_VALUE / .htaccess diagnostics</td><td class="py-1.5">INI-warning consumer before request init (619)</td></tr>
                <tr><td class="py-1.5 font-mono">pm.max_requests</td><td class="py-1.5">producer + consumer must hit the <strong>same worker</strong></td></tr>
              </tbody></table></div>
              <p class="mt-2 text-[11px] text-slate-500 dark:text-slate-400"><strong>Deliverable:</strong> “SAPI=FPM, 8.4.26, unpatched, <code class="font-mono">memory_limit=256M</code>, multipart accepted, upload progress on, workers long-lived → advisory preconditions present; exploitation not tested.”</p>
            </div></li>
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-amber-500 text-xs font-bold text-white">6</span><div class="min-w-0 flex-1">
              <p class="font-bold text-slate-900 dark:text-white">Reproduce in a safe twin of the stack — never on production.</p>
              <p class="mt-1">Use this lab as the twin, loopback only. Follow the per-CVE workbooks: identify the exact source revision and vendor regression test, build a <strong>separate diagnostic image</strong> with symbols + sanitizer (the release image has none), bound memory/time, use synthetic markers only, and repeat against a verified patched image with identical config.</p>
              <div class="mt-2 overflow-x-auto rounded-xl bg-slate-950 p-3 font-mono text-[11px] text-slate-200">
                <p>docker build --build-arg PHP_IMAGE='php:8.4.26-fpm-alpine' -t php2shell-investigation ./php2shell-lab</p>
                <p>docker run -d --name php2shell-investigation --memory=256m --cpus=1 \</p>
                <p>&nbsp;&nbsp;-p 127.0.0.1:8080:80 php2shell-investigation</p>
                <p>python3 cve-demonstrations/collect_runtime.py --port 8080 &gt; baseline.json</p>
                <p>docker logs --timestamps php2shell-investigation &gt; baseline-container.log 2&gt;&amp;1</p>
                <p>docker inspect php2shell-investigation &gt; baseline-container-inspect.json</p>
              </div>
              <div class="mt-2 rounded-xl border border-rose-300/50 bg-rose-50 px-3 py-2 text-[11px] leading-relaxed text-rose-900 dark:border-rose-500/20 dark:bg-rose-500/10 dark:text-rose-200"><strong>Not evidence:</strong> a normal <code class="font-mono">Allowed memory size exhausted</code> error, an OOM-killed container, HTTP 500, worker segfault, matching response text, or persisted session data. A memory disclosure is not automatically RCE. With only those, report <strong>“not reproduced / insufficient evidence”</strong>.</div>
              <p class="mt-2 text-[11px] text-slate-500 dark:text-slate-400">For 619: pin one worker (<code class="font-mono">pm=static, pm.max_children=1, pm.max_requests=0</code>), log worker PIDs, confirm request A and B hit the same PID, add a fresh-worker control, then repeat on the patched image.</p>
            </div></li>
          </ol>
        </div>

        <!-- ── Phase C ── -->
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-bold text-slate-900 dark:text-white">Phase C — Prove, report, retest <span class="ml-1 font-mono text-xs font-normal text-slate-400">steps 7–10</span></h3>
          <ol class="mt-4 space-y-5 text-xs leading-relaxed text-slate-700 dark:text-slate-300">
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-emerald-600 text-xs font-bold text-white">7</span><div class="min-w-0 flex-1">
              <p class="font-bold text-slate-900 dark:text-white">Label your claim with an evidence ladder.</p>
              <div class="mt-2 overflow-x-auto"><table class="w-full text-left text-[11px]"><thead class="uppercase tracking-wider text-slate-400"><tr><th class="py-1.5">Tier</th><th class="py-1.5">What you have</th><th class="py-1.5">Honest claim</th></tr></thead><tbody class="divide-y divide-slate-100 dark:divide-slate-800">
                <tr><td class="py-1.5 font-mono">L0</td><td class="py-1.5">.php URL / PHPSESSID / X-Powered-By only</td><td class="py-1.5">PHP likely present; version unknown</td></tr>
                <tr><td class="py-1.5 font-mono">L1</td><td class="py-1.5">version string / package below fixed milestone</td><td class="py-1.5"><strong>Potentially affected</strong>; backport unverified</td></tr>
                <tr><td class="py-1.5 font-mono">L2</td><td class="py-1.5">L1 + SAPI + patch status + attack requirements</td><td class="py-1.5"><strong>Likely exposed</strong>; no exploit attempted</td></tr>
                <tr><td class="py-1.5 font-mono">L3</td><td class="py-1.5">+ sanitizer/debugger trace tied to source revision + patched control</td><td class="py-1.5">Confirmed defect in this build</td></tr>
                <tr><td class="py-1.5 font-mono">L4</td><td class="py-1.5">+ full demonstrated code-execution chain</td><td class="py-1.5">Confirmed RCE — isolated lab only</td></tr>
              </tbody></table></div>
              <p class="mt-2 text-[11px] text-slate-500 dark:text-slate-400">Most engagements end at <strong>L2</strong> — for a critical pre-auth engine bug that is plenty to prioritise patching. Never present L1 as L4.</p>
            </div></li>
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-emerald-600 text-xs font-bold text-white">8</span><div class="min-w-0 flex-1">
              <p class="font-bold text-slate-900 dark:text-white">Hunt for past abuse if the host was unpatched after 21 Oct 2026.</p>
              <div class="mt-2 overflow-x-auto rounded-xl bg-slate-950 p-3 font-mono text-[11px] text-slate-200">
                <p class="text-slate-400"># PHP/FPM error logs: OOM, timeouts, early diagnostics, crashes</p>
                <p>grep -iE 'Allowed memory size exhausted|Unknown on line 0|Maximum execution time exceeded|SIGSEGV|signal 11|PHP (Warning|Deprecated|Fatal)' /var/log/php*-fpm.log /var/log/nginx/error.log</p>
                <p>journalctl --since '2026-10-20' | grep -iE 'php-fpm.*(segfault|core|exited)'</p>
                <p class="text-slate-400"># Access logs + EDR: upload-progress probes, worker spawning a shell</p>
                <p>grep -iE 'PHP_SESSION_UPLOAD_PROGRESS|multipart/form-data' /var/log/nginx/access.log | head</p>
              </div>
              <p class="mt-2 text-[11px] text-slate-500 dark:text-slate-400"><strong>Highest-value signal:</strong> a PHP worker (<code class="font-mono">php-fpm</code>, <code class="font-mono">php-cgi</code>, <code class="font-mono">httpd</code>) spawning <code class="font-mono">sh/bash/curl/wget/nc/python</code>. CISA published a SIGMA rule for exactly this and recommends monitoring worker processes. Enable <code class="font-mono">log_errors=On</code>, <code class="font-mono">error_reporting=E_ALL</code>, <code class="font-mono">catch_workers_output=yes</code> so the evidence exists.</p>
            </div></li>
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-emerald-600 text-xs font-bold text-white">9</span><div class="min-w-0 flex-1">
              <p class="font-bold text-slate-900 dark:text-white">Write the finding so someone else can reproduce your conclusion.</p>
              <div class="mt-2 overflow-x-auto rounded-xl bg-slate-950 p-3 font-mono text-[11px] leading-relaxed text-slate-200">
                <p class="text-slate-400"># Report skeleton — full template in the companion workbook</p>
                <p>Title: Unpatched PHP engine on &lt;asset&gt; — CVE-2026-109618 / -109619</p>
                <p>Severity: Critical 9.2 (CVSS v4.0 AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H)</p>
                <p>Asset + owner + exposure + image/package digest</p>
                <p>Evidence tier: L1 | L2 | L3 (state which, and why)</p>
                <p>Build + SAPI + how observed (command, response, timestamp)</p>
                <p>Backport check reference (vendor changelog)</p>
                <p>Effective config: memory_limit, post_max_size, upload progress,</p>
                <p>&nbsp;&nbsp;fatal_error_backtraces, per-request INI, pm.max_requests</p>
                <p>Log/EDR hunt result + time window · lab reproduction result</p>
                <p>Impact: pre-auth RCE possible per vendor advisory;</p>
                <p>&nbsp;&nbsp;EXPLOITABILITY NOT TESTED on this asset (if true)</p>
                <p>Caveats: banners can be spoofed; backports change patch status;</p>
                <p>&nbsp;&nbsp;a crash/500 does not prove RCE</p>
                <p>Fix: 8.5.12/8.4.27/8.3.36/8.2.35 or vendor package + restart workers</p>
                <p>Temporary (NOT a fix): memory_limit=-1, low post_max_size + front-end</p>
                <p>&nbsp;&nbsp;caps, session.upload_progress.enabled=0, PHP 8.5</p>
                <p>&nbsp;&nbsp;fatal_error_backtraces=0, no RLIMIT_AS/RLIMIT_DATA</p>
              </div>
            </div></li>
            <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-emerald-600 text-xs font-bold text-white">10</span><div class="min-w-0 flex-1">
              <p class="font-bold text-slate-900 dark:text-white">Retest after patching and close with evidence.</p>
              <ul class="mt-2 grid gap-1.5 sm:grid-cols-2 list-none pl-0 text-[11px] text-slate-600 dark:text-slate-400">
                <li>☐ New version + image digest recorded</li><li>☐ All PHP workers restarted (check start times)</li>
                <li>☐ <code class="font-mono">php -i</code> / <code class="font-mono">php-fpm -tt</code> re-read for the web SAPI</li><li>☐ Temporary mitigations kept or removed with rationale</li>
                <li>☐ Embedded/appliance PHP in separate vendor tickets</li><li>☐ Detection rules deployed and log visibility verified</li>
                <li>☐ Identical workbook steps re-run on the patched build</li><li>☐ Finding closed with evidence, or re-opened with a reason</li>
              </ul>
            </div></li>
          </ol>
        </div>

        <!-- practice + mistakes + sources -->
        <div class="grid gap-4 lg:grid-cols-2">
          <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">Practice path — 10 exercises in this lab</h3>
            <ol class="mt-3 list-decimal space-y-1.5 pl-5 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              <li>Write the detection hypothesis from the primary sources.</li>
              <li>Fingerprint the lab twice (headers + <code class="font-mono">?api=ping</code>).</li>
              <li>Inventory your own machine (images, Dockerfiles, packages).</li>
              <li>Build 8.4.26 <em>and</em> 8.4.27; record both digests.</li>
              <li>Read effective config inside the container (<code class="font-mono">php -i</code>, <code class="font-mono">nginx -T</code>).</li>
              <li>Assign an evidence tier to a version-only observation.</li>
              <li>Write the report from the step-9 template.</li>
              <li>Hunt <code class="font-mono">docker logs</code> and nginx logs; explain why an OOM error is not proof.</li>
              <li>Repeat the workbook steps on the patched image.</li>
              <li>Teach the 10-step loop back to a teammate.</li>
            </ol>
            <p class="mt-3 rounded-xl bg-slate-50 px-3 py-2 text-[11px] leading-relaxed text-slate-500 dark:bg-slate-800/60 dark:text-slate-400"><strong>Beginner traps:</strong> trusting <code class="font-mono">X-Powered-By</code> alone; forgetting distro backports; testing only the CLI SAPI; copying a public PoC into a client environment; calling a crash/500/memory leak “RCE”; forgetting same-worker PID correlation for 619; not restarting workers after patching.</p>
          </div>
          <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">Primary sources — start here, not with blogs</h3>
            <ul class="mt-3 space-y-2 text-xs leading-relaxed">
              <li><a class="font-mono text-indigo-600 hover:underline dark:text-indigo-400" href="https://www.php.net/archive/2026.php#2026-10-21-5" target="_blank" rel="noopener noreferrer">php.net/archive/2026.php#2026-10-21-5</a> — official PHP security advisory and mitigations</li>
              <li><a class="font-mono text-indigo-600 hover:underline dark:text-indigo-400" href="https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w" target="_blank" rel="noopener noreferrer">GHSA-w8hw-w9fx-j79w</a> — CVE-2026-109618 (OOM corruption)</li>
              <li><a class="font-mono text-indigo-600 hover:underline dark:text-indigo-400" href="https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp" target="_blank" rel="noopener noreferrer">GHSA-6wmf-4rv5-p3rp</a> — CVE-2026-109619 (stale global state)</li>
              <li><a class="font-mono text-indigo-600 hover:underline dark:text-indigo-400" href="https://www.cve.org/CVERecord?id=CVE-2026-109618" target="_blank" rel="noopener noreferrer">cve.org/CVERecord?id=CVE-2026-109618</a> · <a class="font-mono text-indigo-600 hover:underline dark:text-indigo-400" href="https://www.cve.org/CVERecord?id=CVE-2026-109619" target="_blank" rel="noopener noreferrer">…-109619</a></li>
              <li><a class="font-mono text-indigo-600 hover:underline dark:text-indigo-400" href="https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching" target="_blank" rel="noopener noreferrer">CISA alert</a> + <a class="font-mono text-indigo-600 hover:underline dark:text-indigo-400" href="https://github.com/cisagov/SIGMA_Rules" target="_blank" rel="noopener noreferrer">SIGMA rules</a> — detection hunting</li>
              <li><a class="font-mono text-indigo-600 hover:underline dark:text-indigo-400" href="https://github.com/NCSC-NL/php2shell" target="_blank" rel="noopener noreferrer">NCSC-NL/php2shell</a> — inventory, affected products, detection material</li>
              <li><a class="font-mono text-indigo-600 hover:underline dark:text-indigo-400" href="https://cert.europa.eu/publications/security-advisories/2026-018" target="_blank" rel="noopener noreferrer">CERT-EU 2026-018</a> — coordinated disclosure timeline</li>
            </ul>
            <p class="mt-3 text-[11px] text-slate-500 dark:text-slate-400">External links need internet; the lab itself stays air-gapped. Companion workbook: <code class="font-mono text-slate-600 dark:text-slate-300">cve-demonstrations/REAL-WORLD-TESTER-GUIDE.md</code>.</p>
          </div>
        </div>
      </div>
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

  /* ── lab tabs (inside Solution view) ──────────────────── */
  (function () {
    var tabs = $$('.lab-tab');
    var panels = $$('[data-lab-panel]');
    if (!tabs.length) return;
    var LAB_ACTIVE = 'lab-tab rounded-full bg-indigo-600 px-4 py-1.5 text-xs font-bold text-white shadow-sm';
    var LAB_IDLE   = 'lab-tab rounded-full border border-slate-200 bg-white px-4 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300';
    var WALK_ACTIVE = 'lab-tab rounded-full bg-emerald-600 px-4 py-1.5 text-xs font-bold text-white shadow-sm';
    var WALK_IDLE   = 'lab-tab rounded-full border border-emerald-300 bg-emerald-50 px-4 py-1.5 text-xs font-bold text-emerald-700 hover:bg-emerald-100 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300';
    var FIELD_ACTIVE = 'lab-tab rounded-full bg-indigo-600 px-4 py-1.5 text-xs font-bold text-white shadow-sm';
    var FIELD_IDLE   = 'lab-tab rounded-full border border-indigo-300 bg-indigo-50 px-4 py-1.5 text-xs font-bold text-indigo-700 hover:bg-indigo-100 dark:border-indigo-500/40 dark:bg-indigo-500/10 dark:text-indigo-300';
    function idleFor(name) {
      if (name === 'walkthrough') return WALK_IDLE;
      if (name === 'field') return FIELD_IDLE;
      return LAB_IDLE;
    }
    function activeFor(name) {
      if (name === 'walkthrough') return WALK_ACTIVE;
      if (name === 'field') return FIELD_ACTIVE;
      return LAB_ACTIVE;
    }
    function activate(name) {
      tabs.forEach(function (b) {
        var n = b.dataset.labTab;
        b.className = n === name ? activeFor(n) : idleFor(n);
      });
      panels.forEach(function (p) { p.classList.toggle('hidden', p.dataset.labPanel !== name); });
    }
    tabs.forEach(function (b) {
      b.addEventListener('click', function () { activate(b.dataset.labTab); });
    });
    // support ?view=lab&tab=walkthrough deep link
    var qs = new URLSearchParams(window.location.search);
    var initial = qs.get('tab') || 'overview';
    var validTabs = ['overview','walkthrough','cve618','cve619','verify','field'];
    if (qs.get('view') === 'lab') { show('lab'); activate(validTabs.indexOf(initial) !== -1 ? initial : 'overview'); }
    // expose for hero buttons
    window.activateLabTab = activate;
  })();

  /* ── walkthrough progress + copy helpers ───────────────── */
  function wtUpdate() {
    var boxes = document.querySelectorAll('[data-wt]');
    var total = boxes.length, done = 0;
    boxes.forEach(function(c){ if(c.checked) done++; });
    var pct = total ? Math.round(done/total*100) : 0;
    var bar = document.getElementById('wt-progress-bar');
    var txt = document.getElementById('wt-progress-text');
    var pctEl = document.getElementById('wt-progress-pct');
    if (bar) bar.style.width = pct + '%';
    if (txt) txt.textContent = done + ' / ' + total + ' tasks';
    if (pctEl) pctEl.textContent = pct + '%';
    // confetti when all done
    if (done === total && total > 0) {
      if (!window._wtDone) { window._wtDone = true; try { toast('🎉 All 12 tasks complete! You solved the lab. Now write your L2 report!'); } catch(e){} }
    } else { window._wtDone = false; }
  }
  function wtLoad() {
    try {
      var data = JSON.parse(localStorage.getItem('wt-progress') || '{}');
      document.querySelectorAll('[data-wt]').forEach(function(c){
        var k = c.getAttribute('data-wt');
        if (data[k]) c.checked = true;
      });
    } catch(e){}
    wtUpdate();
  }
  function wtSave() {
    var data = {};
    document.querySelectorAll('[data-wt]').forEach(function(c){
      data[c.getAttribute('data-wt')] = c.checked;
    });
    try { localStorage.setItem('wt-progress', JSON.stringify(data)); } catch(e){}
    wtUpdate();
  }
  function wtReset() {
    document.querySelectorAll('[data-wt]').forEach(function(c){ c.checked = false; });
    try { localStorage.removeItem('wt-progress'); } catch(e){}
    wtUpdate();
    toast('Progress reset');
  }
  // expose globally for inline handlers
  window.wtReset = wtReset;
  window.wtUpdate = wtUpdate;
  window.wtSave = wtSave;
  document.addEventListener('DOMContentLoaded', function(){
    document.querySelectorAll('[data-wt]').forEach(function(c){
      c.addEventListener('change', wtSave);
    });
    wtLoad();
  });
  // run now in case DOM already loaded
  wtLoad();
  document.querySelectorAll('[data-wt]').forEach(function(c){ c.addEventListener('change', wtSave); });

  function copyCode(btn) {
    var raw = btn.getAttribute('data-code') || '';
    // fallback: try to find next pre code
    if (!raw) {
      var pre = btn.closest('div')?.nextElementSibling?.querySelector('code');
      if (pre) raw = pre.textContent;
    }
    navigator.clipboard.writeText(raw).then(function(){
      var orig = btn.textContent;
      btn.textContent = 'Copied ✓';
      setTimeout(function(){ btn.textContent = orig; }, 1200);
      toast('Copied to clipboard');
    }).catch(function(){
      toast('Copy failed — select manually');
    });
  }
  window.copyCode = copyCode;

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

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
            header('Content-Disposition: inline; filename=\"WALKTHROUGH.md\"');
            readfile($p);
            exit;
        }
    }
    http_response_code(404);
    header('Content-Type: text/plain');
    echo \"WALKTHROUGH.md not found in image. Rebuild with COPY WALKTHROUGH.md included.\";\n    exit;\n}

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

      <!-- ══ WALKTHROUGH (BEGINNER) panel — shows walkthrough.md rendered + interactive guide ══ -->
      <div data-lab-panel="walkthrough" class="hidden space-y-6">
        <!-- Beginner hero -->
        <div class="overflow-hidden rounded-2xl border border-emerald-300 bg-gradient-to-br from-emerald-50 via-white to-indigo-50 shadow-sm dark:border-emerald-500/25 dark:from-emerald-500/10 dark:via-slate-900 dark:to-indigo-500/10">
          <div class="px-6 py-6 sm:px-8 sm:py-7">
            <div class="flex flex-wrap items-center gap-2">
              <span class="inline-flex items-center gap-1.5 rounded-full bg-emerald-600 px-3 py-1 text-[11px] font-bold text-white">🌱 BEGINNER FRIENDLY</span>
              <span class="inline-flex items-center gap-1.5 rounded-full bg-indigo-600 px-3 py-1 text-[11px] font-bold text-white">WALKTHROUGH.MD</span>
              <span class="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white px-3 py-1 text-[11px] font-mono font-semibold text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">12 Tasks · 90-120 min</span>
              <span class="inline-flex items-center gap-1.5 rounded-full bg-amber-100 px-3 py-1 text-[11px] font-bold text-amber-800 dark:bg-amber-500/15 dark:text-amber-300">No hacking experience needed</span>
            </div>
            <h2 class="mt-3 text-xl font-bold tracking-tight text-slate-900 dark:text-white sm:text-2xl">📖 Complete Walkthrough — Find BOTH CVEs Step-by-Step</h2>
            <p class="mt-2 max-w-3xl text-sm leading-relaxed text-slate-600 dark:text-slate-300">This tab shows the full <code class="font-mono font-semibold">WALKTHROUGH.md</code> file rendered for the web — the same TryHackMe / Hack-The-Box style guide that lives in the repo. It’s been enhanced for beginners: plain-English explanations, copy buttons, progress tracking, and “what to do if stuck” tips. <strong>Follow it top-to-bottom and you will find both CVEs and solve the lab.</strong></p>
            <div class="mt-4 flex flex-wrap gap-2">
              <a href="?walkthrough=raw" target="_blank" class="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-bold text-white shadow-sm hover:bg-emerald-500">📄 Open raw WALKTHROUGH.md</a>
              <button type="button" onclick="document.getElementById('wt-content')?.scrollIntoView({behavior:'smooth'})" class="rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">Jump to guide ↓</button>
              <a href="#wt-beginner-map" class="rounded-lg border border-indigo-300 bg-indigo-50 px-4 py-2 text-xs font-bold text-indigo-700 hover:bg-indigo-100 dark:border-indigo-500/40 dark:bg-indigo-500/10 dark:text-indigo-300">See 12-step map</a>
            </div>
            <!-- progress bar -->
            <div class="mt-6 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800/60">
              <div class="flex items-center justify-between">
                <p class="text-xs font-bold text-slate-900 dark:text-white">Your progress</p>
                <p class="text-xs text-slate-500"><span id="wt-progress-text">0 / 12 tasks</span> · <span id="wt-progress-pct">0%</span></p>
              </div>
              <div class="mt-2 h-2.5 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-700">
                <div id="wt-progress-bar" class="h-full rounded-full bg-gradient-to-r from-emerald-500 to-indigo-600 transition-all duration-500" style="width: 0%"></div>
              </div>
              <p class="mt-2 text-[11px] text-slate-400">Check off tasks as you complete them — progress saves in your browser.</p>
            </div>
          </div>
        </div>

        <!-- Beginner quick-start 3-column -->
        <div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div class="flex items-center gap-2">
              <span class="grid h-8 w-8 place-items-center rounded-lg bg-emerald-50 text-emerald-600 dark:bg-emerald-500/10">1</span>
              <h3 class="text-sm font-bold text-slate-900 dark:text-white">What you’ll learn</h3>
            </div>
            <ul class="mt-3 space-y-1.5 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              <li>✔️ How to spot PHP version &amp; patch status</li>
              <li>✔️ What makes each CVE exploitable (config)</li>
              <li>✔️ How to collect evidence professionals use</li>
              <li>✔️ Why a crash ≠ a hack (evidence ladder L0-L4)</li>
              <li>✔️ How to patch &amp; prove the fix</li>
            </ul>
          </div>
          <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div class="flex items-center gap-2">
              <span class="grid h-8 w-8 place-items-center rounded-lg bg-amber-50 text-amber-600 dark:bg-amber-500/10">2</span>
              <h3 class="text-sm font-bold text-slate-900 dark:text-white">You need (all free)</h3>
            </div>
            <ul class="mt-3 space-y-1.5 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              <li>• Docker Desktop (install first)</li>
              <li>• Terminal: <code class="font-mono">bash</code> / <code class="font-mono">zsh</code></li>
              <li>• <code class="font-mono">curl</code>, <code class="font-mono">python3</code> (pre-installed on Mac/Linux)</li>
              <li>• This lab on <code class="font-mono">127.0.0.1:8080</code> (loopback only)</li>
              <li>• 15 min per task, no rushing</li>
            </ul>
          </div>
          <div class="rounded-2xl border border-rose-200 bg-rose-50 p-5 dark:border-rose-500/25 dark:bg-rose-500/10">
            <div class="flex items-center gap-2">
              <span class="grid h-8 w-8 place-items-center rounded-lg bg-white text-rose-600 dark:bg-slate-800">⚠️</span>
              <h3 class="text-sm font-bold text-rose-900 dark:text-rose-200">Safety first</h3>
            </div>
            <ul class="mt-3 space-y-1.5 text-xs leading-relaxed text-rose-800/80 dark:text-rose-200/80">
              <li>• Bind to <code class="font-mono">127.0.0.1</code> only — never <code class="font-mono">0.0.0.0</code></li>
              <li>• Never test on sites you don’t own</li>
              <li>• No exploit payloads needed to pass</li>
              <li>• 500 / OOM = not RCE (you’ll learn why in Task 8)</li>
              <li>• Delete container when done: <code class="font-mono">docker rm -f</code></li>
            </ul>
          </div>
        </div>

        <!-- 12-step visual map -->
        <div id="wt-beginner-map" class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-bold text-slate-900 dark:text-white">🗺️ The 12 tasks — your roadmap to solving the lab</h3>
          <p class="mt-1 text-xs leading-relaxed text-slate-500 dark:text-slate-400">Each task teaches one skill. Tasks 1-6 = find the bug, Tasks 7-8 = understand the bug deeply, Tasks 9-12 = report, detect, patch, and clean up. <strong>Complete Tasks 1-9 for a full solution (L2); Tasks 10-12 make you job-ready.</strong></p>
          <div class="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <div class="group rounded-xl border border-slate-200 p-3 hover:border-emerald-300 hover:bg-emerald-50/50 dark:border-slate-700 dark:hover:bg-emerald-500/5"><p class="text-xs font-bold text-slate-900 dark:text-white"><span class="mr-1 rounded-full bg-indigo-600 px-2 py-0.5 text-[10px] text-white">1</span> Start & verify</p><p class="mt-1 text-[11px] leading-relaxed text-slate-500">Is the lab running? Check healthz + ping + supervisord. ✅ Checkpoint: 4×200 codes.</p></div>
            <div class="group rounded-xl border border-slate-200 p-3 hover:border-emerald-300 hover:bg-emerald-50/50 dark:border-slate-700 dark:hover:bg-emerald-500/5"><p class="text-xs font-bold text-slate-900 dark:text-white"><span class="mr-1 rounded-full bg-indigo-600 px-2 py-0.5 text-[10px] text-white">2</span> Black-box recon</p><p class="mt-1 text-[11px] leading-relaxed text-slate-500">What does the internet see? Headers leak PHP version. Draw nginx→FPM map.</p></div>
            <div class="group rounded-xl border border-slate-200 p-3 hover:border-emerald-300 hover:bg-emerald-50/50 dark:border-slate-700 dark:hover:bg-emerald-500/5"><p class="text-xs font-bold text-slate-900 dark:text-white"><span class="mr-1 rounded-full bg-indigo-600 px-2 py-0.5 text-[10px] text-white">3</span> Fingerprint engine</p><p class="mt-1 text-[11px] leading-relaxed text-slate-500"><strong>Key:</strong> 8.4.26 fpm-fcgi vs cli. Record base digest + image ID.</p></div>
            <div class="group rounded-xl border border-slate-200 p-3 hover:border-emerald-300 hover:bg-emerald-50/50 dark:border-slate-700 dark:hover:bg-emerald-500/5"><p class="text-xs font-bold text-slate-900 dark:text-white"><span class="mr-1 rounded-full bg-amber-500 px-2 py-0.5 text-[10px] text-white">4</span> Patch triage</p><p class="mt-1 text-[11px] leading-relaxed text-slate-500">Is 8.4.26 before the fix? Yes: 8.4.27 is patched. Learn GHSA→CVE mapping.</p></div>
            <div class="group rounded-xl border border-slate-200 p-3 hover:border-emerald-300 hover:bg-emerald-50/50 dark:border-slate-700 dark:hover:bg-emerald-500/5"><p class="text-xs font-bold text-slate-900 dark:text-white"><span class="mr-1 rounded-full bg-amber-500 px-2 py-0.5 text-[10px] text-white">5</span> Attack requirements</p><p class="mt-1 text-[11px] leading-relaxed text-slate-500"><code class="font-mono">memory_limit</code>, <code class="font-mono">post_max_size</code>, <code class="font-mono">upload_progress</code>, workers — can attacker reach the bug?</p></div>
            <div class="group rounded-xl border border-slate-200 p-3 hover:border-emerald-300 hover:bg-emerald-50/50 dark:border-slate-700 dark:hover:bg-emerald-500/5"><p class="text-xs font-bold text-slate-900 dark:text-white"><span class="mr-1 rounded-full bg-amber-500 px-2 py-0.5 text-[10px] text-white">6</span> Baseline evidence</p><p class="mt-1 text-[11px] leading-relaxed text-slate-500">Run <code class="font-mono">collect_runtime.py</code> → baseline.json + hashes. This is your proof.</p></div>
            <div class="group rounded-xl border border-slate-200 p-3 hover:border-emerald-300 hover:bg-emerald-50/50 dark:border-slate-700 dark:hover:bg-emerald-500/5"><p class="text-xs font-bold text-slate-900 dark:text-white"><span class="mr-1 rounded-full bg-violet-600 px-2 py-0.5 text-[10px] text-white">7</span> Worker lifecycle</p><p class="mt-1 text-[11px] leading-relaxed text-slate-500">Pin 1 worker, watch PIDs. <strong>Same PID = CVE-2026-109619 works.</strong></p></div>
            <div class="group rounded-xl border border-slate-200 p-3 hover:border-emerald-300 hover:bg-emerald-50/50 dark:border-slate-700 dark:hover:bg-emerald-500/5"><p class="text-xs font-bold text-slate-900 dark:text-white"><span class="mr-1 rounded-full bg-violet-600 px-2 py-0.5 text-[10px] text-white">8</span> OOM control</p><p class="mt-1 text-[11px] leading-relaxed text-slate-500">Trigger memory_limit on BOTH builds → same 500. So 500 ≠ exploit!</p></div>
            <div class="group rounded-xl border border-slate-200 p-3 hover:border-emerald-300 hover:bg-emerald-50/50 dark:border-slate-700 dark:hover:bg-emerald-500/5"><p class="text-xs font-bold text-slate-900 dark:text-white"><span class="mr-1 rounded-full bg-emerald-600 px-2 py-0.5 text-[10px] text-white">9</span> Write L2 report</p><p class="mt-1 text-[11px] leading-relaxed text-slate-500">One-page finding: asset + patch status + config + caveats + fix.</p></div>
            <div class="group rounded-xl border border-slate-200 p-3 hover:border-emerald-300 hover:bg-emerald-50/50 dark:border-slate-700 dark:hover:bg-emerald-500/5"><p class="text-xs font-bold text-slate-900 dark:text-white"><span class="mr-1 rounded-full bg-slate-600 px-2 py-0.5 text-[10px] text-white">10</span> Detection hunt</p><p class="mt-1 text-[11px] leading-relaxed text-slate-500">Grep logs. Best signal: PHP worker → shell.</p></div>
            <div class="group rounded-xl border border-slate-200 p-3 hover:border-emerald-300 hover:bg-emerald-50/50 dark:border-slate-700 dark:hover:bg-emerald-500/5"><p class="text-xs font-bold text-slate-900 dark:text-white"><span class="mr-1 rounded-full bg-slate-600 px-2 py-0.5 text-[10px] text-white">11</span> Patch & retest</p><p class="mt-1 text-[11px] leading-relaxed text-slate-500">Rebuild 8.4.27, restart workers, re-run all checks.</p></div>
            <div class="group rounded-xl border border-slate-200 p-3 hover:border-emerald-300 hover:bg-emerald-50/50 dark:border-slate-700 dark:hover:bg-emerald-500/5"><p class="text-xs font-bold text-slate-900 dark:text-white"><span class="mr-1 rounded-full bg-slate-600 px-2 py-0.5 text-[10px] text-white">12</span> Teardown</p><p class="mt-1 text-[11px] leading-relaxed text-slate-500">Remove vulnerable image. No trace left.</p></div>
          </div>
        </div>

        <!-- How to find BOTH CVEs — beginner summary -->
        <div class="rounded-2xl border border-indigo-200 bg-indigo-50 p-5 dark:border-indigo-500/20 dark:bg-indigo-500/10">
          <h3 class="text-sm font-bold text-indigo-900 dark:text-indigo-200">🎯 How you find BOTH CVEs (beginner summary before diving in)</h3>
          <div class="mt-3 grid gap-3 sm:grid-cols-2">
            <div class="rounded-xl bg-white p-4 dark:bg-slate-800">
              <p class="text-xs font-bold text-indigo-900 dark:text-indigo-200">CVE-2026-109618 — OOM corruption <span class="ml-1 rounded-full bg-indigo-100 px-2 py-0.5 text-[10px] font-bold text-indigo-700 dark:bg-indigo-500/20">Task 4 + 5 + 8</span></p>
              <ul class="mt-2 list-disc space-y-1 pl-4 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                <li><strong>In plain English:</strong> PHP gets a huge upload, runs out of memory, and “forgets” to clean up. Next thing it does uses dirty memory → RCE.</li>
                <li><strong>How you find it:</strong> You prove <code class="font-mono">PHP 8.4.26 &lt; 8.4.27</code> + <code class="font-mono">fpm-fcgi</code> + <code class="font-mono">memory_limit=256M</code> + multipart allowed (24M). That’s L2. You show a normal OOM error happens on BOTH versions — so you don’t over-claim. Real L3 needs a sanitizer trace (advanced).</li>
                <li><strong>Your proof in lab:</strong> Task 5’s <code class="font-mono">memory_limit</code> line + Task 8’s identical 500 on both builds.</li>
              </ul>
            </div>
            <div class="rounded-xl bg-white p-4 dark:bg-slate-800">
              <p class="text-xs font-bold text-rose-900 dark:text-rose-200">CVE-2026-109619 — Stale global <span class="ml-1 rounded-full bg-rose-100 px-2 py-0.5 text-[10px] font-bold text-rose-700 dark:bg-rose-500/20">Task 4 + 5 + 7</span></p>
              <ul class="mt-2 list-disc space-y-1 pl-4 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                <li><strong>In plain English:</strong> PHP frees memory but leaves a pointer. Next request on the <em>same worker</em> uses the old pointer → leak / RCE.</li>
                <li><strong>How you find it:</strong> You prove <code class="font-mono">8.4.26</code> + <code class="font-mono">fpm-fcgi</code> + <code class="font-mono">session.upload_progress.enabled=On</code> + <code class="font-mono">pm.max_requests=0</code> (workers never recycle). That’s L2 and FPM-validated!</li>
                <li><strong>Your proof in lab:</strong> Task 7 — pin 1 worker, show same PID, show fresh-worker control breaks it.</li>
              </ul>
            </div>
          </div>
          <p class="mt-3 rounded-lg bg-white px-3 py-2 text-xs leading-relaxed text-slate-600 dark:bg-slate-800 dark:text-slate-300"><strong>Rule for both:</strong> No exploit needed! A clean L2 report (“likely exposed — version + SAPI + attack requirements present, no exploit tested”) is enough to force an emergency patch. That’s how you solve the lab as a beginner.</p>
        </div>

        <!-- Interactive checklist for 12 tasks -->
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">✅ Interactive checklist — track your 12 tasks</h3>
            <span class="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-500 dark:bg-slate-800 dark:text-slate-400">saves automatically</span>
            <button type="button" onclick="wtReset()" class="ml-auto rounded-full border border-slate-200 px-3 py-1 text-[11px] font-semibold text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300">Reset</button>
          </div>
          <div class="mt-4 grid gap-2 sm:grid-cols-2">
            <label class="flex items-center gap-3 rounded-xl border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/50"><input type="checkbox" data-wt="1" class="h-4 w-4 rounded border-slate-300 text-emerald-600"><span class="text-xs"><strong>Task 1</strong> — Lab is running (4×200, supervisord)</span></label>
            <label class="flex items-center gap-3 rounded-xl border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/50"><input type="checkbox" data-wt="2" class="h-4 w-4 rounded border-slate-300 text-emerald-600"><span class="text-xs"><strong>Task 2</strong> — Drew nginx→FPM map + headers</span></label>
            <label class="flex items-center gap-3 rounded-xl border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/50"><input type="checkbox" data-wt="3" class="h-4 w-4 rounded border-slate-300 text-emerald-600"><span class="text-xs"><strong>Task 3</strong> — Fingerprint 8.4.26 fpm-fcgi + digests</span></label>
            <label class="flex items-center gap-3 rounded-xl border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/50"><input type="checkbox" data-wt="4" class="h-4 w-4 rounded border-slate-300 text-emerald-600"><span class="text-xs"><strong>Task 4</strong> — Patch triage: 8.4.26 unpatched</span></label>
            <label class="flex items-center gap-3 rounded-xl border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/50"><input type="checkbox" data-wt="5" class="h-4 w-4 rounded border-slate-300 text-emerald-600"><span class="text-xs"><strong>Task 5</strong> — Attack requirements mapped</span></label>
            <label class="flex items-center gap-3 rounded-xl border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/50"><input type="checkbox" data-wt="6" class="h-4 w-4 rounded border-slate-300 text-emerald-600"><span class="text-xs"><strong>Task 6</strong> — Baseline collector + hashes</span></label>
            <label class="flex items-center gap-3 rounded-xl border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/50"><input type="checkbox" data-wt="7" class="h-4 w-4 rounded border-slate-300 text-emerald-600"><span class="text-xs"><strong>Task 7</strong> — Same-PID vs recycled worker</span></label>
            <label class="flex items-center gap-3 rounded-xl border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/50"><input type="checkbox" data-wt="8" class="h-4 w-4 rounded border-slate-300 text-emerald-600"><span class="text-xs"><strong>Task 8</strong> — OOM on both builds = not proof</span></label>
            <label class="flex items-center gap-3 rounded-xl border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/50"><input type="checkbox" data-wt="9" class="h-4 w-4 rounded border-slate-300 text-emerald-600"><span class="text-xs"><strong>Task 9</strong> — L2 report written</span></label>
            <label class="flex items-center gap-3 rounded-xl border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/50"><input type="checkbox" data-wt="10" class="h-4 w-4 rounded border-slate-300 text-emerald-600"><span class="text-xs"><strong>Task 10</strong> — Log hunt / detection</span></label>
            <label class="flex items-center gap-3 rounded-xl border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/50"><input type="checkbox" data-wt="11" class="h-4 w-4 rounded border-slate-300 text-emerald-600"><span class="text-xs"><strong>Task 11</strong> — Patch to 8.4.27 + retest</span></label>
            <label class="flex items-center gap-3 rounded-xl border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800/50"><input type="checkbox" data-wt="12" class="h-4 w-4 rounded border-slate-300 text-emerald-600"><span class="text-xs"><strong>Task 12</strong> — Teardown, no trace left</span></label>
          </div>
        </div>

        <!-- Full WALKTHROUGH.md rendered -->
        <div class="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
            <div>
              <h3 class="text-sm font-bold text-slate-900 dark:text-white">📄 WALKTHROUGH.md — full guide (rendered)</h3>
              <p class="text-[11px] text-slate-400">This is the exact <code class="font-mono">WALKTHROUGH.md</code> from the repo, rendered with beginner styling. Use the table of contents to jump.</p>
            </div>
            <div class="flex gap-2">
              <a href="?walkthrough=raw" target="_blank" class="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-[11px] font-semibold text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">Raw markdown</a>
              <button type="button" onclick="document.getElementById('wt-content')?.scrollTo({top:0,behavior:'smooth'})" class="rounded-full bg-slate-900 px-3 py-1.5 text-[11px] font-bold text-white hover:bg-slate-700 dark:bg-white dark:text-slate-900">Back to top ↑</button>
            </div>
          </div>
          <div id="wt-content" class="scroll-thin max-h-[70vh] overflow-y-auto px-6 py-6">
            <?= walkthrough_file_html() ?>
          </div>
        </div>

        <!-- Beginner glossary quick ref -->
        <div class="rounded-2xl border border-amber-300 bg-amber-50 p-5 dark:border-amber-500/20 dark:bg-amber-500/10">
          <h3 class="text-sm font-bold text-amber-900 dark:text-amber-200">📚 Quick glossary — hover any term in the guide</h3>
          <div class="mt-3 grid gap-2 sm:grid-cols-2 text-xs leading-relaxed text-amber-900/80 dark:text-amber-200/80">
            <p><strong>CVE</strong> = ID for a bug. <strong>CVSS</strong> = severity score. <strong>RCE</strong> = attacker runs code.</p>
            <p><strong>SAPI</strong> = how PHP runs: fpm-fcgi (web), cli (terminal). Need web SAPI.</p>
            <p><strong>Docker</strong> = sandbox computer. <strong>nginx</strong> = front door. <strong>PHP-FPM</strong> = PHP workers.</p>
            <p><strong>memory_limit</strong> = max per request. <strong>post_max_size</strong> = max upload size.</p>
            <p><strong>pm.max_requests</strong> = when to recycle worker. 0 = never (good for 109619).</p>
            <p><strong>L2</strong> = “likely exposed” — your goal. <strong>L4</strong> = full hack — not needed.</p>
          </div>
        </div>
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

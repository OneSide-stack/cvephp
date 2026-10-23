<?php
declare(strict_types=1);
header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Assessment Portal</title>
<style>body{font-family:Arial,sans-serif;background:#f0f2f5;color:#1d2935;max-width:900px;margin:40px auto;padding:0 20px}header{border-left:5px solid #246b61;padding-left:18px}main{background:white;padding:24px;border:1px solid #ccd4dc;border-radius:5px}a{color:#175e75}code,pre{font-family:monospace}pre{background:#111b24;color:#d8e6e8;padding:14px;overflow:auto}.warning{background:#fff4db;padding:12px;border-left:4px solid #cc8b25}nav a{margin-right:18px}</style></head>
<body><header><h1>Assessment Portal</h1><p>Enterprise application security assessment · isolated host 192.168.10.55</p></header>
<main><nav><a href="/">Overview</a><a href="/wp-login.php">Sign in</a><a href="/info.php">Runtime information</a><a href="/health.php">Health JSON</a></nav>
<h2>Custom PHP training application</h2><p>This site is served by the target guest's Apache and mod_php processes. It is <strong>not WordPress</strong>. The login route is a WordPress-style training workflow only.</p>
<p class="warning"><strong>Authorized isolated lab only.</strong> Request-processing research can terminate workers. Use the attacker guest and inspect real target evidence.</p>
<h3>Assessment scope</h3><ul><li>HTTP service on 192.168.10.55:80</li><li>PHP request startup and multipart handling</li><li>Apache access, error, and PHP error logs</li></ul>
<h3>Baseline request</h3><pre>curl --noproxy '*' -i http://192.168.10.55/health.php</pre>
<p>No application endpoint executes shell commands, writes arbitrary files, or returns a flag on demand.</p>
</main></body></html>

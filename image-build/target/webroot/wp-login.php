<?php
declare(strict_types=1);
header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
$message = '';
$status = 200;
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $user = isset($_POST['log']) && is_string($_POST['log']) ? $_POST['log'] : '';
    $pass = isset($_POST['pwd']) && is_string($_POST['pwd']) ? $_POST['pwd'] : '';
    // A deliberately ordinary training login, not an exploitation shortcut.
    if (hash_equals('analyst', $user) && hash_equals('range', $pass)) {
        $message = 'Training credentials accepted. No administrative session is required for this lab.';
    } else {
        $message = 'Invalid training credentials. Hint: analyst / range';
        $status = 403;
    }
    http_response_code($status);
}
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Log In ‹ Assessment Portal</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f0f0f1;color:#3c434a;margin:0;padding:60px 16px}main{max-width:360px;margin:auto}h1{text-align:center;font-size:25px}form{background:#fff;border:1px solid #c3c4c7;padding:26px;box-shadow:0 1px 3px #00000013}label{display:block;font-size:14px;margin:12px 0 5px}input{width:100%;box-sizing:border-box;font-size:20px;padding:7px;border:1px solid #8c8f94}button{background:#2271b1;color:white;border:0;padding:10px 15px;font-size:14px;margin-top:18px}p.notice{border-left:4px solid #72aee6;background:#fff;padding:12px}.error{border-left-color:#d63638}small{display:block;text-align:center;margin-top:20px}</style></head>
<body><main><h1>Assessment Portal</h1><?php if ($message !== ''): ?><p class="notice<?= $status === 403 ? ' error' : '' ?>"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></p><?php endif; ?>
<form method="post" action="/wp-login.php"><label for="user_login">Username or Email Address</label><input id="user_login" name="log" autocomplete="username" required><label for="user_pass">Password</label><input id="user_pass" name="pwd" type="password" autocomplete="current-password" required><button type="submit">Log In</button></form>
<p><a href="/">← Back to Assessment Portal</a></p><small>WordPress-style training page · not a WordPress installation</small></main></body></html>

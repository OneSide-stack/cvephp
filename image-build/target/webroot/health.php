<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');
$limit = ini_get('memory_limit');
$result = [
    'service' => 'assessment-portal',
    'application' => 'custom-php-training-application',
    'wordpress' => false,
    'php_version' => PHP_VERSION,
    'php_sapi' => PHP_SAPI,
    'memory_limit' => $limit,
    'post_max_size' => ini_get('post_max_size'),
    'upload_max_filesize' => ini_get('upload_max_filesize'),
    'max_file_uploads' => (int) ini_get('max_file_uploads'),
    'upload_progress' => (bool) ini_get('session.upload_progress.enabled'),
    'apache' => function_exists('apache_get_version') ? apache_get_version() : null,
    'worker_pid' => getmypid(),
    'time' => gmdate('c'),
];
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";

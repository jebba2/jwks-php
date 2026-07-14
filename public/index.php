<?php

/**
 * JWKS endpoint front controller. Serves the key set at GET
 * /.well-known/jwks.json and at the site root, under both Apache (via
 * FallbackResource/.htaccess) and the built-in PHP web server (as its
 * router script).
 */

declare(strict_types=1);

use Jwks\Endpoint;
use Jwks\EnvFile;
use Jwks\JwksBuilder;
use Jwks\KeyStore;
use Jwks\Logger;

require dirname(__DIR__) . '/vendor/autoload.php';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri = $_SERVER['REQUEST_URI'] ?? '/';

$logger = null;

try {
    EnvFile::load(dirname(__DIR__) . '/.env');
    $logger = Logger::fromEnvironment();

    // Private keys live in JWKS_KEYS_DIR if set, otherwise working/keys at
    // the project root (outside the document root).
    $keysDirectory = getenv('JWKS_KEYS_DIR');
    if (!is_string($keysDirectory) || $keysDirectory === '') {
        $keysDirectory = dirname(__DIR__) . '/working/keys';
    }

    $endpoint = new Endpoint(new JwksBuilder(new KeyStore($keysDirectory)));
    $response = $endpoint->handle(
        is_string($method) ? $method : 'GET',
        is_string($uri) ? $uri : '/',
    );
} catch (Throwable $exception) {
    if ($logger !== null) {
        $logger->error('endpoint: ' . $exception->getMessage());
    } else {
        // The logger itself could not be built (e.g. malformed .env).
        error_log('jwks endpoint error: ' . $exception->getMessage());
    }
    $response = [
        'status' => 500,
        'headers' => ['Content-Type' => 'application/json'],
        'body' => '{"error":"internal server error"}',
    ];
}

http_response_code($response['status']);
foreach ($response['headers'] as $name => $value) {
    header($name . ': ' . $value);
}
echo $response['body'];

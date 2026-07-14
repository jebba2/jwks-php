<?php

declare(strict_types=1);

namespace Jwks\Tests;

use Jwks\KeyGenerator;
use Jwks\KeyStore;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end test: boots the real built-in PHP web server against
 * public/index.php and fetches the key set over real HTTP.
 */
final class BuiltInServerTest extends TestCase
{
    private string $directory;

    /** @var resource|null */
    private $serverProcess;

    private string $baseUrl = '';

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/jwks-test-' . bin2hex(random_bytes(8));
        $this->startServer();
    }

    protected function tearDown(): void
    {
        if (is_resource($this->serverProcess)) {
            proc_terminate($this->serverProcess);
            proc_close($this->serverProcess);
        }

        if (is_dir($this->directory)) {
            $files = glob($this->directory . '/*');
            $this->assertIsArray($files);
            foreach ($files as $file) {
                unlink($file);
            }
            rmdir($this->directory);
        }
    }

    private function startServer(): void
    {
        $port = $this->findFreePort();
        $this->baseUrl = 'http://127.0.0.1:' . $port;
        $projectRoot = dirname(__DIR__);

        $process = proc_open(
            [
                PHP_BINARY,
                '-S',
                '127.0.0.1:' . $port,
                '-t',
                $projectRoot . '/public',
                $projectRoot . '/public/index.php',
            ],
            [
                1 => ['file', '/dev/null', 'w'],
                2 => ['file', '/dev/null', 'w'],
            ],
            $pipes,
            $projectRoot,
            ['JWKS_KEYS_DIR' => $this->directory],
        );
        $this->assertIsResource($process);
        $this->serverProcess = $process;

        $this->waitUntilServerAccepts($port);
    }

    private function findFreePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
        $this->assertIsResource($socket, "could not probe for a free port: $errorMessage");

        $name = stream_socket_get_name($socket, false);
        $this->assertIsString($name);
        fclose($socket);

        $port = (int) substr($name, (int) strrpos($name, ':') + 1);
        $this->assertGreaterThan(0, $port);

        return $port;
    }

    private function waitUntilServerAccepts(int $port): void
    {
        $deadline = microtime(true) + 10.0;
        while (microtime(true) < $deadline) {
            $connection = @stream_socket_client('tcp://127.0.0.1:' . $port, $errorCode, $errorMessage, 0.25);
            if (is_resource($connection)) {
                fclose($connection);

                return;
            }
            usleep(50_000);
        }

        $this->fail('built-in PHP server did not start listening within 10 seconds');
    }

    /**
     * @return array{status: int, headers: list<string>, body: string}
     */
    private function httpGet(string $path): array
    {
        $context = stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 5.0]]);
        $http_response_header = [];
        $body = file_get_contents($this->baseUrl . $path, false, $context);
        $this->assertIsString($body, "request to $path failed");
        $this->assertNotSame([], $http_response_header);

        $statusParts = explode(' ', $http_response_header[0]);
        $this->assertArrayHasKey(1, $statusParts);

        return [
            'status' => (int) $statusParts[1],
            'headers' => $http_response_header,
            'body' => $body,
        ];
    }

    private function headerValue(string $name, string ...$headers): string
    {
        foreach ($headers as $header) {
            if (stripos($header, $name . ':') === 0) {
                return trim(substr($header, strlen($name) + 1));
            }
        }
        $this->fail("response is missing the $name header");
    }

    public function testServesGeneratedKeyOverHttp(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add(new KeyGenerator()->generate());

        $response = $this->httpGet('/.well-known/jwks.json');

        $this->assertSame(200, $response['status']);
        $this->assertStringContainsString(
            'application/json',
            $this->headerValue('Content-Type', ...$response['headers']),
        );

        $decoded = json_decode($response['body'], true);
        $this->assertIsArray($decoded);
        $this->assertArrayHasKey('keys', $decoded);
        $this->assertIsArray($decoded['keys']);
        $this->assertCount(1, $decoded['keys']);
        $this->assertIsArray($decoded['keys'][0]);
        $this->assertSame($kid, $decoded['keys'][0]['kid']);
        $this->assertSame('RSA', $decoded['keys'][0]['kty']);
        $this->assertArrayNotHasKey('d', $decoded['keys'][0], 'private material must never be served');
    }

    public function testServesKeySetAtRootOverHttp(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add(new KeyGenerator()->generate());

        $response = $this->httpGet('/');

        $this->assertSame(200, $response['status']);

        $decoded = json_decode($response['body'], true);
        $this->assertIsArray($decoded);
        $this->assertArrayHasKey('keys', $decoded);
        $this->assertIsArray($decoded['keys']);
        $this->assertCount(1, $decoded['keys']);
        $this->assertIsArray($decoded['keys'][0]);
        $this->assertSame($kid, $decoded['keys'][0]['kid']);
    }

    public function testExpiredKeysAreNotServedAndActiveKeysPublishExpiry(): void
    {
        $store = new KeyStore($this->directory);
        $now = time();
        $expiredKid = $store->add(new KeyGenerator()->generate(), notBefore: 0, expiresAt: $now - 60);
        $activeKid = $store->add(new KeyGenerator()->generate(), notBefore: 0, expiresAt: $now + 3600);

        $response = $this->httpGet('/.well-known/jwks.json');

        $this->assertSame(200, $response['status']);
        $decoded = json_decode($response['body'], true);
        $this->assertIsArray($decoded);
        $this->assertArrayHasKey('keys', $decoded);
        $this->assertIsArray($decoded['keys']);
        $this->assertCount(1, $decoded['keys']);
        $this->assertIsArray($decoded['keys'][0]);
        $this->assertSame($activeKid, $decoded['keys'][0]['kid']);
        $this->assertSame($now + 3600, $decoded['keys'][0]['exp']);
        $this->assertStringNotContainsString($expiredKid, $response['body']);
    }

    public function testUnknownPathReturns404OverHttp(): void
    {
        $response = $this->httpGet('/nope');

        $this->assertSame(404, $response['status']);
    }
}

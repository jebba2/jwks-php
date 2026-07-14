<?php

declare(strict_types=1);

namespace Jwks\Tests;

use Jwks\Endpoint;
use Jwks\JwksBuilder;
use Jwks\KeyGenerator;
use Jwks\KeyLifecycle;
use Jwks\KeyStore;
use Jwks\RotationPolicy;
use PHPUnit\Framework\TestCase;

final class EndpointTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/jwks-test-' . bin2hex(random_bytes(8));
    }

    protected function tearDown(): void
    {
        if (is_dir($this->directory)) {
            $files = glob($this->directory . '/*');
            $this->assertIsArray($files);
            foreach ($files as $file) {
                unlink($file);
            }
            rmdir($this->directory);
        }
    }

    private function endpoint(): Endpoint
    {
        $store = new KeyStore($this->directory);
        $policy = new RotationPolicy(keyLifetime: 3000, rotationBuffer: 1000, timeUntilUse: 300);

        return new Endpoint(
            new JwksBuilder($store),
            new KeyLifecycle($store, new KeyGenerator(), $policy),
        );
    }

    private function endpointWithOneKey(): Endpoint
    {
        new KeyStore($this->directory)->add(new KeyGenerator()->generate());

        return $this->endpoint();
    }

    public function testServesKeySetAtWellKnownPath(): void
    {
        $response = $this->endpointWithOneKey()->handle('GET', '/.well-known/jwks.json');

        $this->assertSame(200, $response['status']);
        $this->assertSame('application/json', $response['headers']['Content-Type']);

        $decoded = json_decode($response['body'], true);
        $this->assertIsArray($decoded);
        $this->assertArrayHasKey('keys', $decoded);
        $this->assertIsArray($decoded['keys']);
        $this->assertCount(1, $decoded['keys']);
    }

    public function testServesKeySetAtRootPath(): void
    {
        $response = $this->endpointWithOneKey()->handle('GET', '/');

        $this->assertSame(200, $response['status']);
        $this->assertSame('application/json', $response['headers']['Content-Type']);

        $decoded = json_decode($response['body'], true);
        $this->assertIsArray($decoded);
        $this->assertArrayHasKey('keys', $decoded);
        $this->assertIsArray($decoded['keys']);
        $this->assertCount(1, $decoded['keys']);
    }

    public function testKeySetResponseIsCacheable(): void
    {
        $response = $this->endpointWithOneKey()->handle('GET', '/.well-known/jwks.json');

        $this->assertArrayHasKey('Cache-Control', $response['headers']);
        $this->assertStringContainsString('max-age', $response['headers']['Cache-Control']);
    }

    public function testHeadRequestIsAccepted(): void
    {
        $response = $this->endpointWithOneKey()->handle('HEAD', '/.well-known/jwks.json');

        $this->assertSame(200, $response['status']);
    }

    public function testIgnoresQueryStringWhenMatchingPath(): void
    {
        $response = $this->endpointWithOneKey()->handle('GET', '/.well-known/jwks.json?cachebust=1');

        $this->assertSame(200, $response['status']);
    }

    public function testUnknownPathReturnsJsonNotFound(): void
    {
        $response = $this->endpointWithOneKey()->handle('GET', '/other');

        $this->assertSame(404, $response['status']);
        $this->assertSame('application/json', $response['headers']['Content-Type']);
        $this->assertJson($response['body']);
    }

    public function testHealthzReportsOkForHealthyKeySet(): void
    {
        $now = time();
        new KeyStore($this->directory)->add(new KeyGenerator()->generate(), $now - 10, $now + 3000);

        $response = $this->endpoint()->handle('GET', '/healthz');

        $this->assertSame(200, $response['status']);
        $this->assertSame('{"status":"ok"}', $response['body']);
        $this->assertSame('no-store', $response['headers']['Cache-Control']);
    }

    public function testHealthzReports503WithoutDetailWhenDegraded(): void
    {
        $response = $this->endpoint()->handle('GET', '/healthz');

        $this->assertSame(503, $response['status']);
        $this->assertSame('{"status":"degraded"}', $response['body']);
    }

    public function testResponsesAllowCrossOriginReads(): void
    {
        $endpoint = $this->endpointWithOneKey();

        $keySet = $endpoint->handle('GET', '/.well-known/jwks.json');
        $notFound = $endpoint->handle('GET', '/other');
        $notAllowed = $endpoint->handle('POST', '/.well-known/jwks.json');

        $this->assertSame('*', $keySet['headers']['Access-Control-Allow-Origin']);
        $this->assertSame('*', $notFound['headers']['Access-Control-Allow-Origin']);
        $this->assertSame('*', $notAllowed['headers']['Access-Control-Allow-Origin']);
    }

    public function testDisallowedMethodReturns405WithAllowHeader(): void
    {
        $response = $this->endpointWithOneKey()->handle('POST', '/.well-known/jwks.json');

        $this->assertSame(405, $response['status']);
        $this->assertSame('GET, HEAD', $response['headers']['Allow']);
    }
}

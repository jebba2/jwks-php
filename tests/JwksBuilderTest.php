<?php

declare(strict_types=1);

namespace Jwks\Tests;

use Jwks\JwksBuilder;
use Jwks\KeyGenerator;
use Jwks\KeyStore;
use PHPUnit\Framework\TestCase;

final class JwksBuilderTest extends TestCase
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

    public function testBuildsEmptyKeySetForEmptyStore(): void
    {
        $builder = new JwksBuilder(new KeyStore($this->directory));

        $this->assertSame(['keys' => []], $builder->build());
    }

    public function testBuildsOnePublicJwkPerStoredKey(): void
    {
        $store = new KeyStore($this->directory);
        $firstKid = $store->add(new KeyGenerator()->generate());
        $secondKid = $store->add(new KeyGenerator()->generate());

        $jwks = new JwksBuilder($store)->build();

        $this->assertCount(2, $jwks['keys']);
        $kids = array_column($jwks['keys'], 'kid');
        $this->assertContains($firstKid, $kids);
        $this->assertContains($secondKid, $kids);
    }

    public function testBuiltKeysContainOnlyPublicMembers(): void
    {
        $store = new KeyStore($this->directory);
        $store->add(new KeyGenerator()->generate());

        $jwks = new JwksBuilder($store)->build();

        $this->assertSame(['kty', 'use', 'alg', 'kid', 'n', 'e'], array_keys($jwks['keys'][0]));
    }

    public function testToJsonProducesValidJwksDocument(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add(new KeyGenerator()->generate());

        $decoded = json_decode(new JwksBuilder($store)->toJson(), true);

        $this->assertIsArray($decoded);
        $this->assertArrayHasKey('keys', $decoded);
        $this->assertIsArray($decoded['keys']);
        $this->assertIsArray($decoded['keys'][0]);
        $this->assertSame($kid, $decoded['keys'][0]['kid']);
    }
}

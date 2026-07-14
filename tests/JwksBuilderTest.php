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

    public function testStampedKeysPublishTheirExpiry(): void
    {
        $store = new KeyStore($this->directory);
        $store->add(new KeyGenerator()->generate(), notBefore: 1000, expiresAt: 2000);

        $jwks = new JwksBuilder($store)->build(now: 1500);

        $this->assertCount(1, $jwks['keys']);
        $this->assertSame(2000, $jwks['keys'][0]['exp'] ?? null);
    }

    public function testExpiredKeysAreNotPublished(): void
    {
        $store = new KeyStore($this->directory);
        $expiredKid = $store->add(new KeyGenerator()->generate(), notBefore: 1000, expiresAt: 2000);
        $activeKid = $store->add(new KeyGenerator()->generate(), notBefore: 1000, expiresAt: 9000);

        $jwks = new JwksBuilder($store)->build(now: 2000);

        $kids = array_column($jwks['keys'], 'kid');
        $this->assertSame([$activeKid], $kids);
        $this->assertNotContains($expiredKid, $kids);
    }

    public function testUnstampedKeysArePublishedWithoutExpiry(): void
    {
        $store = new KeyStore($this->directory);
        $store->add(new KeyGenerator()->generate());

        $jwks = new JwksBuilder($store)->build();

        $this->assertCount(1, $jwks['keys']);
        $this->assertArrayNotHasKey('exp', $jwks['keys'][0]);
    }

    public function testKeysNotYetUsableAreStillPublished(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add(new KeyGenerator()->generate(), notBefore: 5000, expiresAt: 9000);

        $jwks = new JwksBuilder($store)->build(now: 1000);

        $this->assertSame([$kid], array_column($jwks['keys'], 'kid'));
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

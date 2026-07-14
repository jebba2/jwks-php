<?php

declare(strict_types=1);

namespace Jwks\Tests;

use InvalidArgumentException;
use Jwks\KeyGenerator;
use PHPUnit\Framework\TestCase;

final class KeyGeneratorTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('JWKS_KEY_BITS');
    }

    public function testGeneratesRsaPrivateKeyPemOf2048BitsByDefault(): void
    {
        $pem = new KeyGenerator()->generate();

        $key = openssl_pkey_get_private($pem);
        $this->assertNotFalse($key, 'generated PEM must be a readable private key');

        $details = openssl_pkey_get_details($key);
        $this->assertNotFalse($details);
        $this->assertSame(OPENSSL_KEYTYPE_RSA, $details['type']);
        $this->assertSame(2048, $details['bits']);
    }

    public function testGeneratesKeyOfRequestedBits(): void
    {
        $pem = new KeyGenerator()->generate(3072);

        $key = openssl_pkey_get_private($pem);
        $this->assertNotFalse($key);

        $details = openssl_pkey_get_details($key);
        $this->assertNotFalse($details);
        $this->assertSame(3072, $details['bits']);
    }

    public function testRejectsBitsBelow2048(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new KeyGenerator()->generate(1024);
    }

    public function testRejectsConfiguredDefaultBitsBelow2048(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $rejected = new KeyGenerator(1024);
    }

    public function testRejectsBitsAbove8192(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new KeyGenerator()->generate(16384);
    }

    public function testRejectsConfiguredDefaultBitsAbove8192(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $rejected = new KeyGenerator(16384);
    }

    public function testFromEnvironmentReadsConfiguredKeyBits(): void
    {
        putenv('JWKS_KEY_BITS=3072');

        $pem = KeyGenerator::fromEnvironment()->generate();

        $key = openssl_pkey_get_private($pem);
        $this->assertNotFalse($key);

        $details = openssl_pkey_get_details($key);
        $this->assertNotFalse($details);
        $this->assertSame(3072, $details['bits']);
    }

    public function testFromEnvironmentUsesMinimumBitsWhenUnset(): void
    {
        $pem = KeyGenerator::fromEnvironment()->generate();

        $key = openssl_pkey_get_private($pem);
        $this->assertNotFalse($key);

        $details = openssl_pkey_get_details($key);
        $this->assertNotFalse($details);
        $this->assertSame(2048, $details['bits']);
    }

    public function testFromEnvironmentRejectsNonNumericBits(): void
    {
        putenv('JWKS_KEY_BITS=big');

        $this->expectException(InvalidArgumentException::class);

        KeyGenerator::fromEnvironment();
    }
}

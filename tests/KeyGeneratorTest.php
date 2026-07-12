<?php

declare(strict_types=1);

namespace Jwks\Tests;

use InvalidArgumentException;
use Jwks\KeyGenerator;
use PHPUnit\Framework\TestCase;

final class KeyGeneratorTest extends TestCase
{
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
}

<?php

declare(strict_types=1);

namespace Jwks\Tests;

use Jwks\Base64Url;
use PHPUnit\Framework\TestCase;

final class Base64UrlTest extends TestCase
{
    public function testEncodesAsciiWithoutPadding(): void
    {
        $this->assertSame('aGVsbG8', Base64Url::encode('hello'));
    }

    public function testEncodesBinaryUsingUrlSafeAlphabet(): void
    {
        $encoded = Base64Url::encode("\xfb\xff\xfe");

        $this->assertSame('-__-', $encoded);
        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
        $this->assertStringNotContainsString('=', $encoded);
    }

    public function testDecodeRoundTripsRandomBinary(): void
    {
        $binary = random_bytes(64);

        $this->assertSame($binary, Base64Url::decode(Base64Url::encode($binary)));
    }
}

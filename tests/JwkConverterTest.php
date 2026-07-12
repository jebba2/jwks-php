<?php

declare(strict_types=1);

namespace Jwks\Tests;

use InvalidArgumentException;
use Jwks\JwkConverter;
use PHPUnit\Framework\TestCase;

final class JwkConverterTest extends TestCase
{
    /**
     * Known-answer vectors computed directly from openssl output for the
     * fixture key, independently of the implementation under test.
     */
    private const string EXPECTED_N = 'lsN7tsJzMezvoIwqFnpVkC38TatpDD15bJNXqk12x6zhZ93FaFjqL6AAcy4NBGtK'
        . 's3wNhrkXegKaGQSami5SM1EW1T769ZFpBc2FW8-5tH-3LYYRRMtXT44R85QOxH8x'
        . 'Fmchhm_eYYQbiFqf_X_E1sy3FabSJ0Ao71I7S9OAMEUfz3yZgnhTM5I2f8MRxwg1'
        . 'JfXCXeZZRpy2LHVHC3sf7NPbNeqUceF8aPkevo_WDMq5QJLII4D-1ioDB0Q8TSlA'
        . 'IjwImaQqqK0rnoxz4QcCHG-vKypPrMiM8sjXXgU9rZ5f7VCiosGroNZnpmmexm_Q'
        . 'g2GBrMtYtUwv-gw3A5UBDQ';
    private const string EXPECTED_E = 'AQAB';
    private const string EXPECTED_KID = 'gXI7LN05n7GL-OahEsEhZpif_kKsenrycOQFDVA_8Gc';

    private function fixturePem(): string
    {
        $pem = file_get_contents(__DIR__ . '/fixtures/test-key.pem');
        $this->assertNotFalse($pem);

        return $pem;
    }

    public function testConvertsPrivatePemToPublicSigningJwk(): void
    {
        $jwk = new JwkConverter()->publicJwkFromPrivatePem($this->fixturePem());

        $this->assertSame('RSA', $jwk['kty']);
        $this->assertSame('sig', $jwk['use']);
        $this->assertSame('RS256', $jwk['alg']);
        $this->assertSame(self::EXPECTED_N, $jwk['n']);
        $this->assertSame(self::EXPECTED_E, $jwk['e']);
    }

    public function testKidIsRfc7638Sha256Thumbprint(): void
    {
        $jwk = new JwkConverter()->publicJwkFromPrivatePem($this->fixturePem());

        $this->assertSame(self::EXPECTED_KID, $jwk['kid']);
    }

    public function testJwkContainsNoPrivateKeyMaterial(): void
    {
        $jwk = new JwkConverter()->publicJwkFromPrivatePem($this->fixturePem());

        $this->assertSame(['kty', 'use', 'alg', 'kid', 'n', 'e'], array_keys($jwk));
    }

    public function testRejectsInvalidPem(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new JwkConverter()->publicJwkFromPrivatePem('not a pem');
    }

    public function testRejectsNonRsaKey(): void
    {
        $ecKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        $this->assertNotFalse($ecKey);
        $exported = openssl_pkey_export($ecKey, $ecPem);
        $this->assertTrue($exported);
        $this->assertIsString($ecPem);

        $this->expectException(InvalidArgumentException::class);

        new JwkConverter()->publicJwkFromPrivatePem($ecPem);
    }
}

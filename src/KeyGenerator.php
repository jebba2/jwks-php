<?php

declare(strict_types=1);

namespace Jwks;

use InvalidArgumentException;
use RuntimeException;

/**
 * Generates RSA private keys for JWT signing.
 */
final class KeyGenerator
{
    /**
     * 2048 bits is the minimum RSA size acceptable for RS256 in production.
     */
    private const int MINIMUM_BITS = 2048;

    /**
     * Generates a new RSA private key and returns it as a PEM string.
     */
    public function generate(int $bits = self::MINIMUM_BITS): string
    {
        if ($bits < self::MINIMUM_BITS) {
            throw new InvalidArgumentException(
                sprintf('RSA keys must be at least %d bits, got %d', self::MINIMUM_BITS, $bits),
            );
        }

        $key = openssl_pkey_new([
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($key === false) {
            throw new RuntimeException('openssl failed to generate an RSA key: ' . self::opensslError());
        }

        if (!openssl_pkey_export($key, $pem) || !is_string($pem)) {
            throw new RuntimeException('openssl failed to export the private key: ' . self::opensslError());
        }

        return $pem;
    }

    /**
     * Returns the most recent openssl error message for diagnostics.
     */
    private static function opensslError(): string
    {
        $error = openssl_error_string();

        return $error === false ? 'unknown error' : $error;
    }
}

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
     * Nothing interoperable uses RSA above 8192 bits; the cap keeps a
     * configuration typo from burning CPU for minutes on every rotation.
     */
    private const int MAXIMUM_BITS = 8192;

    public function __construct(private readonly int $defaultBits = self::MINIMUM_BITS)
    {
        self::assertAcceptableBits($defaultBits);
    }

    /**
     * Builds a generator whose default key size comes from the
     * JWKS_KEY_BITS environment variable (minimum 2048 when unset).
     */
    public static function fromEnvironment(): self
    {
        $value = getenv('JWKS_KEY_BITS');
        if (!is_string($value) || $value === '') {
            return new self();
        }

        if (!ctype_digit($value)) {
            throw new InvalidArgumentException(
                "JWKS_KEY_BITS must be a positive integer, got \"$value\"",
            );
        }

        return new self((int) $value);
    }

    /**
     * Generates a new RSA private key and returns it as a PEM string. With
     * no argument the configured default size is used.
     */
    public function generate(?int $bits = null): string
    {
        $bits ??= $this->defaultBits;
        self::assertAcceptableBits($bits);

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
     * Rejects key sizes outside the supported range.
     */
    private static function assertAcceptableBits(int $bits): void
    {
        if ($bits < self::MINIMUM_BITS || $bits > self::MAXIMUM_BITS) {
            throw new InvalidArgumentException(sprintf(
                'RSA keys must be between %d and %d bits, got %d',
                self::MINIMUM_BITS,
                self::MAXIMUM_BITS,
                $bits,
            ));
        }
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

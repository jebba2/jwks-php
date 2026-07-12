<?php

declare(strict_types=1);

namespace Jwks;

use InvalidArgumentException;

/**
 * Derives the public JWK (RFC 7517) for an RSA private key.
 */
final class JwkConverter
{
    /**
     * Converts an RSA private key PEM into its public signing JWK.
     * Only public members are included; private key material never leaves here.
     *
     * @return array{kty: string, use: string, alg: string, kid: string, n: string, e: string}
     */
    public function publicJwkFromPrivatePem(string $privatePem): array
    {
        $key = openssl_pkey_get_private($privatePem);
        if ($key === false) {
            throw new InvalidArgumentException('value is not a readable private key PEM');
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_RSA) {
            throw new InvalidArgumentException('key is not an RSA key');
        }

        $rsa = $details['rsa'] ?? null;
        if (!is_array($rsa) || !is_string($rsa['n'] ?? null) || !is_string($rsa['e'] ?? null)) {
            throw new InvalidArgumentException('key is missing RSA public components');
        }

        $modulus = Base64Url::encode($rsa['n']);
        $exponent = Base64Url::encode($rsa['e']);

        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => self::thumbprint($modulus, $exponent),
            'n' => $modulus,
            'e' => $exponent,
        ];
    }

    /**
     * Computes the RFC 7638 SHA-256 thumbprint used as the key id: the hash
     * of the required JWK members in lexicographic order with no whitespace.
     */
    private static function thumbprint(string $modulus, string $exponent): string
    {
        $canonical = '{"e":"' . $exponent . '","kty":"RSA","n":"' . $modulus . '"}';

        return Base64Url::encode(hash('sha256', $canonical, true));
    }
}

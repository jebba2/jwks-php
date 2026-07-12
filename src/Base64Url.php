<?php

declare(strict_types=1);

namespace Jwks;

use InvalidArgumentException;

/**
 * Base64url encoding as required by JWK members (RFC 7515 section 2):
 * the URL-safe alphabet with no padding.
 */
final class Base64Url
{
    /**
     * Encodes binary data as unpadded base64url.
     */
    public static function encode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    /**
     * Decodes an unpadded base64url string back to binary.
     */
    public static function decode(string $encoded): string
    {
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);
        if ($decoded === false) {
            throw new InvalidArgumentException('value is not valid base64url');
        }

        return $decoded;
    }
}

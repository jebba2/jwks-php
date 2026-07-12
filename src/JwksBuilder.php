<?php

declare(strict_types=1);

namespace Jwks;

/**
 * Builds the public JWKS document (RFC 7517) from the keys in a KeyStore.
 */
final class JwksBuilder
{
    public function __construct(private readonly KeyStore $store)
    {
    }

    /**
     * Builds the key set as an array with one public JWK per stored key.
     *
     * @return array{keys: list<array{kty: string, use: string, alg: string, kid: string, n: string, e: string}>}
     */
    public function build(): array
    {
        $converter = new JwkConverter();

        $keys = [];
        foreach ($this->store->kids() as $kid) {
            $keys[] = $converter->publicJwkFromPrivatePem($this->store->privatePem($kid));
        }

        return ['keys' => $keys];
    }

    /**
     * Builds the key set as the JSON document served to clients.
     */
    public function toJson(): string
    {
        return json_encode($this->build(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}

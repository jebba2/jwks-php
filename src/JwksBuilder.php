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
     * Expired keys are omitted; keys under rotation publish their expiry as
     * the exp member (as D2L does) so verifiers can see rotation coming.
     *
     * @return array{
     *     keys: list<array{kty: string, use: string, alg: string, kid: string, n: string, e: string, exp?: int}>
     * }
     */
    public function build(?int $now = null): array
    {
        $now ??= time();
        $converter = new JwkConverter();

        $keys = [];
        foreach ($this->store->kids() as $kid) {
            $metadata = $this->store->metadata($kid);
            if ($metadata !== null && $metadata['expiresAt'] <= $now) {
                continue;
            }

            $jwk = $converter->publicJwkFromPrivatePem($this->store->privatePem($kid));
            if ($metadata !== null) {
                $jwk['exp'] = $metadata['expiresAt'];
            }
            $keys[] = $jwk;
        }

        return ['keys' => $keys];
    }

    /**
     * Builds the key set as the JSON document served to clients.
     */
    public function toJson(?int $now = null): string
    {
        return json_encode($this->build($now), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}

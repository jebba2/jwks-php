<?php

declare(strict_types=1);

namespace Jwks;

/**
 * HTTP handler for the JWKS endpoint. SAPI-agnostic: it maps a request
 * method and URI to a response array so the same logic runs under Apache,
 * the built-in PHP server, and unit tests.
 */
final class Endpoint
{
    public const string KEY_SET_PATH = '/.well-known/jwks.json';

    /**
     * Verifiers may cache the key set for this long; RotationPolicy keeps
     * every key published at least this long before it signs anything.
     */
    public const int CACHE_MAX_AGE_SECONDS = 300;

    private const string CACHE_CONTROL = 'public, max-age=' . self::CACHE_MAX_AGE_SECONDS;

    /**
     * JWKS documents hold only public keys, so browser-based verifiers may
     * read them cross-origin.
     */
    private const array COMMON_HEADERS = [
        'Content-Type' => 'application/json',
        'Access-Control-Allow-Origin' => '*',
    ];

    public function __construct(private readonly JwksBuilder $builder)
    {
    }

    /**
     * Handles one request and returns the response to send.
     *
     * @return array{status: int, headers: array<string, string>, body: string}
     */
    public function handle(string $method, string $uri): array
    {
        if (!in_array($method, ['GET', 'HEAD'], true)) {
            return [
                'status' => 405,
                'headers' => self::COMMON_HEADERS + ['Allow' => 'GET, HEAD'],
                'body' => '{"error":"method not allowed"}',
            ];
        }

        // The key set is served at the RFC 8615 well-known path and, for
        // convenience, at the site root.
        $path = parse_url($uri, PHP_URL_PATH);
        if (!in_array($path, [self::KEY_SET_PATH, '/'], true)) {
            return [
                'status' => 404,
                'headers' => self::COMMON_HEADERS,
                'body' => '{"error":"not found"}',
            ];
        }

        return [
            'status' => 200,
            'headers' => self::COMMON_HEADERS + ['Cache-Control' => self::CACHE_CONTROL],
            'body' => $this->builder->toJson(),
        ];
    }
}

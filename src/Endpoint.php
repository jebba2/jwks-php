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
     * Up/degraded signal for external HTTP monitors; an empty-but-valid
     * key set still returns 200 on the key-set paths, so uptime checks
     * need this instead.
     */
    public const string HEALTH_PATH = '/healthz';

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

    public function __construct(
        private readonly JwksBuilder $builder,
        private readonly KeyLifecycle $lifecycle,
    ) {
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

        $path = parse_url($uri, PHP_URL_PATH);

        if ($path === self::HEALTH_PATH) {
            // Degraded reasons stay in "jwks status"; the wire only carries
            // up/degraded so operational detail is not public.
            $healthy = $this->lifecycle->healthProblems() === [];

            return [
                'status' => $healthy ? 200 : 503,
                'headers' => self::COMMON_HEADERS + ['Cache-Control' => 'no-store'],
                'body' => $healthy ? '{"status":"ok"}' : '{"status":"degraded"}',
            ];
        }

        // The key set is served at the RFC 8615 well-known path and, for
        // convenience, at the site root.
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

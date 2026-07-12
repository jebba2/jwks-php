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
     * Verifiers may cache the key set briefly; keep the window shorter than
     * any key-rotation overlap period.
     */
    private const string CACHE_CONTROL = 'public, max-age=300';

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
                'headers' => [
                    'Content-Type' => 'application/json',
                    'Allow' => 'GET, HEAD',
                ],
                'body' => '{"error":"method not allowed"}',
            ];
        }

        $path = parse_url($uri, PHP_URL_PATH);
        if ($path !== self::KEY_SET_PATH) {
            return [
                'status' => 404,
                'headers' => ['Content-Type' => 'application/json'],
                'body' => '{"error":"not found"}',
            ];
        }

        return [
            'status' => 200,
            'headers' => [
                'Content-Type' => 'application/json',
                'Cache-Control' => self::CACHE_CONTROL,
            ],
            'body' => $this->builder->toJson(),
        ];
    }
}

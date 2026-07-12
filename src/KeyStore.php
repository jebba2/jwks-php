<?php

declare(strict_types=1);

namespace Jwks;

use InvalidArgumentException;
use RuntimeException;

/**
 * File-based store for RSA signing keys. Each key lives in one PEM file
 * named by its kid; the directory and files are owner-access only because
 * they hold private key material.
 */
final class KeyStore
{
    /**
     * Kids are base64url thumbprints, so anything else is rejected before
     * it can reach the filesystem.
     */
    private const string KID_PATTERN = '/^[A-Za-z0-9_-]+$/';

    public function __construct(private readonly string $directory)
    {
        if (!is_dir($directory) && !mkdir($directory, 0o700, true) && !is_dir($directory)) {
            throw new RuntimeException("could not create key directory $directory");
        }
    }

    /**
     * Stores a private key and returns its kid. Adding the same key twice
     * is a no-op because the kid is derived from the key itself.
     */
    public function add(string $privatePem): string
    {
        $kid = new JwkConverter()->publicJwkFromPrivatePem($privatePem)['kid'];
        $path = $this->pathFor($kid);

        $temporaryPath = $path . '.tmp';
        if (file_put_contents($temporaryPath, $privatePem) === false) {
            throw new RuntimeException("could not write key file $temporaryPath");
        }
        if (!chmod($temporaryPath, 0o600) || !rename($temporaryPath, $path)) {
            unlink($temporaryPath);
            throw new RuntimeException("could not install key file $path");
        }

        return $kid;
    }

    /**
     * Returns the kids of all stored keys, sorted for stable output.
     *
     * @return list<string>
     */
    public function kids(): array
    {
        $files = glob($this->directory . '/*.pem');
        if ($files === false) {
            throw new RuntimeException("could not list key directory {$this->directory}");
        }

        $kids = array_map(static fn(string $file): string => basename($file, '.pem'), $files);
        sort($kids);

        return $kids;
    }

    /**
     * Returns the private key PEM for a stored kid.
     */
    public function privatePem(string $kid): string
    {
        $path = $this->existingPathFor($kid);

        $pem = file_get_contents($path);
        if ($pem === false) {
            throw new RuntimeException("could not read key file $path");
        }

        return $pem;
    }

    /**
     * Permanently removes a key. Tokens signed with it can no longer be
     * verified against this key set.
     */
    public function retire(string $kid): void
    {
        $path = $this->existingPathFor($kid);

        if (!unlink($path)) {
            throw new RuntimeException("could not delete key file $path");
        }
    }

    /**
     * Validates a kid and returns the file path it would be stored at.
     */
    private function pathFor(string $kid): string
    {
        if (preg_match(self::KID_PATTERN, $kid) !== 1) {
            throw new InvalidArgumentException("invalid kid: $kid");
        }

        return $this->directory . '/' . $kid . '.pem';
    }

    /**
     * Validates a kid and returns its file path, requiring the key to exist.
     */
    private function existingPathFor(string $kid): string
    {
        $path = $this->pathFor($kid);
        if (!is_file($path)) {
            throw new RuntimeException("unknown key: $kid");
        }

        return $path;
    }
}

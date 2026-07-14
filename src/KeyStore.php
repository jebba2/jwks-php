<?php

declare(strict_types=1);

namespace Jwks;

use InvalidArgumentException;
use RuntimeException;

/**
 * File-based store for RSA signing keys. Each key lives in one PEM file
 * named by its kid; the directory and files are owner-access only because
 * they hold private key material. Keys under rotation carry a JSON sidecar
 * (<kid>.json) recording when the key may start signing and when it expires.
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
     * is a no-op because the kid is derived from the key itself. Passing
     * notBefore and expiresAt (both or neither) records the key's rotation
     * lifecycle alongside it.
     */
    public function add(string $privatePem, ?int $notBefore = null, ?int $expiresAt = null): string
    {
        if (($notBefore === null) !== ($expiresAt === null)) {
            throw new InvalidArgumentException('notBefore and expiresAt must be given together');
        }

        $kid = new JwkConverter()->publicJwkFromPrivatePem($privatePem)['kid'];
        $path = $this->pathFor($kid);

        $this->installFile($path, $privatePem);
        if ($notBefore !== null && $expiresAt !== null) {
            $this->writeMetadata($kid, $notBefore, $expiresAt);
        }

        return $kid;
    }

    /**
     * Returns a stored key's rotation lifecycle, or null for keys created
     * before rotation existed (they never expire until stamped).
     *
     * @return array{notBefore: int, expiresAt: int}|null
     */
    public function metadata(string $kid): ?array
    {
        $this->existingPathFor($kid);

        $path = $this->metadataPathFor($kid);
        if (!is_file($path)) {
            return null;
        }

        $json = file_get_contents($path);
        if ($json === false) {
            throw new RuntimeException("could not read key metadata file $path");
        }

        $decoded = json_decode($json, true);
        if (
            !is_array($decoded)
            || !is_int($decoded['notBefore'] ?? null)
            || !is_int($decoded['expiresAt'] ?? null)
        ) {
            throw new RuntimeException("malformed key metadata file $path");
        }

        return ['notBefore' => $decoded['notBefore'], 'expiresAt' => $decoded['expiresAt']];
    }

    /**
     * Records the rotation lifecycle of an existing key.
     */
    public function stamp(string $kid, int $notBefore, int $expiresAt): void
    {
        $this->existingPathFor($kid);

        $this->writeMetadata($kid, $notBefore, $expiresAt);
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
     * Returns the path of the lock file that serializes rotation passes so
     * concurrent rotates cannot both generate a successor.
     */
    public function rotationLockPath(): string
    {
        return $this->directory . '/rotate.lock';
    }

    /**
     * Returns the filesystem path of a stored key's PEM file, for token
     * issuers that read the private key directly.
     */
    public function pemPath(string $kid): string
    {
        return $this->existingPathFor($kid);
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

        $metadataPath = $this->metadataPathFor($kid);
        if (is_file($metadataPath) && !unlink($metadataPath)) {
            throw new RuntimeException("could not delete key metadata file $metadataPath");
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

    /**
     * Returns the path of the lifecycle sidecar for a validated kid.
     */
    private function metadataPathFor(string $kid): string
    {
        $this->pathFor($kid);

        return $this->directory . '/' . $kid . '.json';
    }

    /**
     * Writes the lifecycle sidecar for a key.
     */
    private function writeMetadata(string $kid, int $notBefore, int $expiresAt): void
    {
        $json = json_encode(
            ['notBefore' => $notBefore, 'expiresAt' => $expiresAt],
            JSON_THROW_ON_ERROR,
        );

        $this->installFile($this->metadataPathFor($kid), $json);
    }

    /**
     * Atomically installs a file with owner-only permissions.
     */
    private function installFile(string $path, string $contents): void
    {
        $temporaryPath = $path . '.tmp';
        if (file_put_contents($temporaryPath, $contents) === false) {
            throw new RuntimeException("could not write key file $temporaryPath");
        }
        if (!chmod($temporaryPath, 0o600) || !rename($temporaryPath, $path)) {
            unlink($temporaryPath);
            throw new RuntimeException("could not install key file $path");
        }
    }
}

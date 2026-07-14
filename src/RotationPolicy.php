<?php

declare(strict_types=1);

namespace Jwks;

use InvalidArgumentException;

/**
 * Timing rules for automatic key rotation, modeled on D2L's OAuth2 service:
 * every key expires keyLifetime after creation, a successor is generated
 * rotationBuffer before that expiry, and a new key is not used for signing
 * until it has been published for timeUntilUse so verifier caches can pick
 * it up. All durations are in seconds.
 */
final class RotationPolicy
{
    public const int DEFAULT_KEY_LIFETIME = 30 * 24 * 60 * 60;

    public const int DEFAULT_ROTATION_BUFFER = 7 * 24 * 60 * 60;

    public const int DEFAULT_TIME_UNTIL_USE = 60 * 60;

    public function __construct(
        public readonly int $keyLifetime = self::DEFAULT_KEY_LIFETIME,
        public readonly int $rotationBuffer = self::DEFAULT_ROTATION_BUFFER,
        public readonly int $timeUntilUse = self::DEFAULT_TIME_UNTIL_USE,
    ) {
        if ($this->keyLifetime <= 0 || $this->rotationBuffer <= 0 || $this->timeUntilUse <= 0) {
            throw new InvalidArgumentException('rotation durations must be positive');
        }

        if ($this->timeUntilUse < Endpoint::CACHE_MAX_AGE_SECONDS) {
            throw new InvalidArgumentException(sprintf(
                'timeUntilUse must be at least the %d-second response cache window, got %d',
                Endpoint::CACHE_MAX_AGE_SECONDS,
                $this->timeUntilUse,
            ));
        }

        if ($this->keyLifetime <= $this->rotationBuffer + $this->timeUntilUse) {
            throw new InvalidArgumentException(sprintf(
                'keyLifetime (%d) must exceed rotationBuffer (%d) plus timeUntilUse (%d)',
                $this->keyLifetime,
                $this->rotationBuffer,
                $this->timeUntilUse,
            ));
        }
    }

    /**
     * Builds a policy from the JWKS_KEY_LIFETIME, JWKS_ROTATION_BUFFER and
     * JWKS_TIME_UNTIL_USE environment variables, using the defaults for any
     * that are unset.
     */
    public static function fromEnvironment(): self
    {
        return new self(
            self::durationFromEnvironment('JWKS_KEY_LIFETIME', self::DEFAULT_KEY_LIFETIME),
            self::durationFromEnvironment('JWKS_ROTATION_BUFFER', self::DEFAULT_ROTATION_BUFFER),
            self::durationFromEnvironment('JWKS_TIME_UNTIL_USE', self::DEFAULT_TIME_UNTIL_USE),
        );
    }

    /**
     * Reads a duration in seconds from an environment variable.
     */
    private static function durationFromEnvironment(string $name, int $default): int
    {
        $value = getenv($name);
        if (!is_string($value) || $value === '') {
            return $default;
        }

        if (!ctype_digit($value)) {
            throw new InvalidArgumentException(
                "$name must be a positive integer number of seconds, got \"$value\"",
            );
        }

        return (int) $value;
    }
}

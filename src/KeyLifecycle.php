<?php

declare(strict_types=1);

namespace Jwks;

use RuntimeException;

/**
 * Drives keys through the D2L-style rotation lifecycle: legacy keys are
 * scheduled for replacement, a successor is generated one rotation buffer
 * before the newest key expires, and keys long past expiry are purged.
 * Also selects the key that should be signing right now.
 */
final class KeyLifecycle
{
    public function __construct(
        private readonly KeyStore $store,
        private readonly KeyGenerator $generator,
        private readonly RotationPolicy $policy,
    ) {
    }

    /**
     * Runs one rotation pass. Idempotent, so it is safe to run from cron at
     * any frequency; concurrent passes serialize on a file lock so they
     * cannot both generate a successor. Returns the kids affected by each
     * action.
     *
     * @return array{stamped: list<string>, generated: ?string, purged: list<string>}
     */
    public function rotate(?int $now = null): array
    {
        $now ??= time();

        $lock = fopen($this->store->rotationLockPath(), 'c');
        if ($lock === false) {
            throw new RuntimeException('could not open rotation lock file ' . $this->store->rotationLockPath());
        }
        if (!flock($lock, LOCK_EX)) {
            fclose($lock);
            throw new RuntimeException('could not acquire the rotation lock');
        }

        try {
            return $this->rotateLocked($now);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * The rotation pass itself; only ever runs under the rotation lock.
     *
     * @return array{stamped: list<string>, generated: ?string, purged: list<string>}
     */
    private function rotateLocked(int $now): array
    {
        $stamped = [];
        foreach ($this->store->kids() as $kid) {
            if ($this->store->metadata($kid) === null) {
                // Legacy keys predate rotation: they stay usable immediately
                // and get replaced one rotation buffer from now.
                $this->store->stamp($kid, $now, $now + $this->policy->rotationBuffer);
                $stamped[] = $kid;
            }
        }

        $purged = [];
        $needsSuccessor = true;
        foreach ($this->store->kids() as $kid) {
            $metadata = $this->store->metadata($kid);
            if ($metadata === null) {
                continue;
            }

            if ($now >= $metadata['expiresAt'] + $this->policy->rotationBuffer) {
                $this->store->retire($kid);
                $purged[] = $kid;
                continue;
            }

            if ($now < $metadata['expiresAt'] - $this->policy->rotationBuffer) {
                $needsSuccessor = false;
            }
        }

        $generated = null;
        if ($needsSuccessor) {
            $generated = $this->store->add(
                $this->generator->generate(),
                $now + $this->policy->timeUntilUse,
                $now + $this->policy->keyLifetime,
            );
        }

        return ['stamped' => $stamped, 'generated' => $generated, 'purged' => $purged];
    }

    /**
     * Health check for monitoring: returns one description per problem, so
     * an empty list means healthy. Degraded states mean the rotate cron is
     * missing, dead, or has not run yet — every problem here is fixed by
     * a successful rotation pass.
     *
     * @return list<string>
     */
    public function healthProblems(?int $now = null): array
    {
        $now ??= time();

        $kids = $this->store->kids();
        if ($kids === []) {
            return ['key set is empty; run "jwks rotate"'];
        }

        $problems = [];
        $hasStampedCurrentKey = false;
        $hasFreshKey = false;
        $newestExpiry = PHP_INT_MIN;
        foreach ($kids as $kid) {
            $metadata = $this->store->metadata($kid);
            if ($metadata === null) {
                $problems[] = "legacy key $kid awaiting first rotation";
                continue;
            }
            if ($metadata['expiresAt'] <= $now) {
                continue;
            }

            $hasStampedCurrentKey = true;
            $newestExpiry = max($newestExpiry, $metadata['expiresAt']);
            if ($now < $metadata['expiresAt'] - $this->policy->rotationBuffer) {
                $hasFreshKey = true;
            }
        }

        if ($this->signingKid($now) === null) {
            $problems[] = 'no usable signing key; every key has expired';
        }

        if ($hasStampedCurrentKey && !$hasFreshKey) {
            $problems[] = 'rotation overdue: newest key expires '
                . gmdate('Y-m-d\TH:i:sP', $newestExpiry) . '; check the rotate cron';
        }

        return $problems;
    }

    /**
     * Returns the kid the token issuer should sign with right now: the
     * newest key that is already usable and not expired, with legacy keys
     * counting as usable but oldest. When no key is usable yet (a brand-new
     * key set), falls back to the pending key that becomes usable soonest —
     * no verifier can hold a stale cache of a key set that never had a
     * usable key. Null when the store is empty or every key has expired.
     */
    public function signingKid(?int $now = null): ?string
    {
        $now ??= time();

        $best = null;
        $bestNotBefore = PHP_INT_MIN;
        $pending = null;
        $pendingNotBefore = PHP_INT_MAX;
        foreach ($this->store->kids() as $kid) {
            $metadata = $this->store->metadata($kid);
            if ($metadata !== null && $metadata['expiresAt'] <= $now) {
                continue;
            }

            // kids() is sorted, so >= and < make ties resolve to the same
            // kid on every host.
            if ($metadata !== null && $metadata['notBefore'] > $now) {
                if ($metadata['notBefore'] < $pendingNotBefore) {
                    $pending = $kid;
                    $pendingNotBefore = $metadata['notBefore'];
                }
                continue;
            }

            $notBefore = $metadata['notBefore'] ?? PHP_INT_MIN;
            if ($best === null || $notBefore >= $bestNotBefore) {
                $best = $kid;
                $bestNotBefore = $notBefore;
            }
        }

        return $best ?? $pending;
    }
}

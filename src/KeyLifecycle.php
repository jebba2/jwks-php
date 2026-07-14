<?php

declare(strict_types=1);

namespace Jwks;

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
     * any frequency. Returns the kids affected by each action.
     *
     * @return array{stamped: list<string>, generated: ?string, purged: list<string>}
     */
    public function rotate(?int $now = null): array
    {
        $now ??= time();

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

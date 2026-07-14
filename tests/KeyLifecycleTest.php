<?php

declare(strict_types=1);

namespace Jwks\Tests;

use Jwks\KeyGenerator;
use Jwks\KeyLifecycle;
use Jwks\KeyStore;
use Jwks\RotationPolicy;
use PHPUnit\Framework\TestCase;

final class KeyLifecycleTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/jwks-test-' . bin2hex(random_bytes(8));
    }

    protected function tearDown(): void
    {
        if (is_dir($this->directory)) {
            $files = glob($this->directory . '/*');
            $this->assertIsArray($files);
            foreach ($files as $file) {
                unlink($file);
            }
            rmdir($this->directory);
        }
    }

    /**
     * Small durations keep the arithmetic in tests readable: keys live 3000s,
     * successors appear 1000s before expiry, new keys sign after 300s.
     */
    private function lifecycle(): KeyLifecycle
    {
        return new KeyLifecycle(
            new KeyStore($this->directory),
            new KeyGenerator(),
            new RotationPolicy(keyLifetime: 3000, rotationBuffer: 1000, timeUntilUse: 300),
        );
    }

    private function store(): KeyStore
    {
        return new KeyStore($this->directory);
    }

    public function testRotateOnEmptyStoreGeneratesFirstKey(): void
    {
        $report = $this->lifecycle()->rotate(now: 10000);

        $this->assertNotNull($report['generated']);
        $this->assertSame([], $report['stamped']);
        $this->assertSame([], $report['purged']);
        $this->assertSame(
            ['notBefore' => 10300, 'expiresAt' => 13000],
            $this->store()->metadata($report['generated']),
        );
    }

    public function testRotateStampsLegacyKeysAndGeneratesTheirReplacement(): void
    {
        $legacyKid = $this->store()->add(new KeyGenerator()->generate());

        $report = $this->lifecycle()->rotate(now: 10000);

        $this->assertSame([$legacyKid], $report['stamped']);
        $this->assertSame(
            ['notBefore' => 10000, 'expiresAt' => 11000],
            $this->store()->metadata($legacyKid),
        );
        $this->assertNotNull($report['generated']);
        $this->assertCount(2, $this->store()->kids());
    }

    public function testRotateDoesNothingWhileTheNewestKeyIsFresh(): void
    {
        $lifecycle = $this->lifecycle();
        $lifecycle->rotate(now: 10000);

        $report = $lifecycle->rotate(now: 10001);

        $this->assertSame(['stamped' => [], 'generated' => null, 'purged' => []], $report);
    }

    public function testRotateGeneratesSuccessorInsideTheRotationBuffer(): void
    {
        $lifecycle = $this->lifecycle();
        $first = $lifecycle->rotate(now: 10000)['generated'];
        $this->assertNotNull($first);

        $report = $lifecycle->rotate(now: 12000);

        $this->assertNotNull($report['generated']);
        $this->assertNotSame($first, $report['generated']);
        $this->assertSame(
            ['notBefore' => 12300, 'expiresAt' => 15000],
            $this->store()->metadata($report['generated']),
        );
        $this->assertContains($first, $this->store()->kids());
    }

    public function testRotatePurgesKeysOneBufferAfterExpiry(): void
    {
        $expiredKid = $this->store()->add(new KeyGenerator()->generate(), notBefore: 0, expiresAt: 1000);

        $report = $this->lifecycle()->rotate(now: 2000);

        $this->assertSame([$expiredKid], $report['purged']);
        $this->assertNotContains($expiredKid, $this->store()->kids());
    }

    public function testRotateKeepsExpiredKeysDuringTheGracePeriod(): void
    {
        $expiredKid = $this->store()->add(new KeyGenerator()->generate(), notBefore: 0, expiresAt: 1500);

        $report = $this->lifecycle()->rotate(now: 2000);

        $this->assertSame([], $report['purged']);
        $this->assertContains($expiredKid, $this->store()->kids());
    }

    public function testSigningKidPrefersTheNewestUsableKey(): void
    {
        $store = $this->store();
        $older = $store->add(new KeyGenerator()->generate(), notBefore: 100, expiresAt: 10000);
        $newer = $store->add(new KeyGenerator()->generate(), notBefore: 200, expiresAt: 10000);

        $this->assertSame($newer, $this->lifecycle()->signingKid(now: 500));
        $this->assertContains($older, $store->kids());
    }

    public function testSigningKidSkipsKeysNotYetUsable(): void
    {
        $store = $this->store();
        $usable = $store->add(new KeyGenerator()->generate(), notBefore: 100, expiresAt: 10000);
        $store->add(new KeyGenerator()->generate(), notBefore: 900, expiresAt: 10000);

        $this->assertSame($usable, $this->lifecycle()->signingKid(now: 500));
    }

    public function testSigningKidSkipsExpiredKeys(): void
    {
        $store = $this->store();
        $store->add(new KeyGenerator()->generate(), notBefore: 100, expiresAt: 400);
        $active = $store->add(new KeyGenerator()->generate(), notBefore: 200, expiresAt: 10000);

        $this->assertSame($active, $this->lifecycle()->signingKid(now: 500));
    }

    public function testSigningKidTreatsUnstampedKeysAsUsableButOldest(): void
    {
        $store = $this->store();
        $unstamped = $store->add(new KeyGenerator()->generate());
        $stamped = $store->add(new KeyGenerator()->generate(), notBefore: 100, expiresAt: 10000);

        $this->assertSame($stamped, $this->lifecycle()->signingKid(now: 500));

        $store->retire($stamped);
        $this->assertSame($unstamped, $this->lifecycle()->signingKid(now: 500));
    }

    public function testSigningKidFallsBackToPendingKeyWhenNoneIsUsableYet(): void
    {
        $store = $this->store();
        $soonest = $store->add(new KeyGenerator()->generate(), notBefore: 900, expiresAt: 10000);
        $store->add(new KeyGenerator()->generate(), notBefore: 950, expiresAt: 10000);

        $this->assertSame($soonest, $this->lifecycle()->signingKid(now: 500));
    }

    public function testHealthProblemsReportsEmptyKeySet(): void
    {
        $problems = $this->lifecycle()->healthProblems(now: 500);

        $this->assertCount(1, $problems);
        $this->assertStringContainsString('empty', $problems[0]);
    }

    public function testHealthProblemsIsEmptyForFreshKey(): void
    {
        $this->store()->add(new KeyGenerator()->generate(), notBefore: 0, expiresAt: 10000);

        $this->assertSame([], $this->lifecycle()->healthProblems(now: 500));
    }

    public function testHealthProblemsFlagsLegacyKeys(): void
    {
        $legacyKid = $this->store()->add(new KeyGenerator()->generate());

        $problems = $this->lifecycle()->healthProblems(now: 500);

        $this->assertCount(1, $problems);
        $this->assertStringContainsString("legacy key $legacyKid", $problems[0]);
    }

    public function testHealthProblemsFlagsOverdueRotation(): void
    {
        // Inside the 1000s rotation buffer with no fresh successor: the
        // cron should have generated one by now.
        $this->store()->add(new KeyGenerator()->generate(), notBefore: 0, expiresAt: 1200);

        $problems = $this->lifecycle()->healthProblems(now: 500);

        $this->assertCount(1, $problems);
        $this->assertStringContainsString('rotation overdue', $problems[0]);
    }

    public function testHealthProblemsFlagsFullyExpiredKeySet(): void
    {
        $this->store()->add(new KeyGenerator()->generate(), notBefore: 0, expiresAt: 400);

        $problems = $this->lifecycle()->healthProblems(now: 500);

        $this->assertCount(1, $problems);
        $this->assertStringContainsString('no usable signing key', $problems[0]);
    }

    public function testSigningKidIsNullForAnEmptyStore(): void
    {
        $this->assertNull($this->lifecycle()->signingKid(now: 500));
    }

    public function testSigningKidIsNullWhenEveryKeyIsExpired(): void
    {
        $this->store()->add(new KeyGenerator()->generate(), notBefore: 100, expiresAt: 400);

        $this->assertNull($this->lifecycle()->signingKid(now: 500));
    }
}

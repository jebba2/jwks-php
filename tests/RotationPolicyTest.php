<?php

declare(strict_types=1);

namespace Jwks\Tests;

use InvalidArgumentException;
use Jwks\RotationPolicy;
use PHPUnit\Framework\TestCase;

final class RotationPolicyTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('JWKS_KEY_LIFETIME');
        putenv('JWKS_ROTATION_BUFFER');
        putenv('JWKS_TIME_UNTIL_USE');
    }

    public function testDefaultsMatchDocumentedDurations(): void
    {
        $policy = new RotationPolicy();

        $this->assertSame(30 * 24 * 60 * 60, $policy->keyLifetime);
        $this->assertSame(7 * 24 * 60 * 60, $policy->rotationBuffer);
        $this->assertSame(60 * 60, $policy->timeUntilUse);
    }

    public function testAcceptsCustomDurations(): void
    {
        $policy = new RotationPolicy(keyLifetime: 7200, rotationBuffer: 1800, timeUntilUse: 300);

        $this->assertSame(7200, $policy->keyLifetime);
        $this->assertSame(1800, $policy->rotationBuffer);
        $this->assertSame(300, $policy->timeUntilUse);
    }

    public function testRejectsNonPositiveKeyLifetime(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new RotationPolicy(keyLifetime: 0);
    }

    public function testRejectsNonPositiveRotationBuffer(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new RotationPolicy(rotationBuffer: 0);
    }

    public function testRejectsTimeUntilUseShorterThanResponseCacheWindow(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new RotationPolicy(timeUntilUse: 299);
    }

    public function testRejectsLifetimeNotLongerThanBufferPlusTimeUntilUse(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new RotationPolicy(keyLifetime: 2100, rotationBuffer: 1800, timeUntilUse: 300);
    }

    public function testFromEnvironmentUsesDefaultsWhenUnset(): void
    {
        $policy = RotationPolicy::fromEnvironment();

        $this->assertSame(RotationPolicy::DEFAULT_KEY_LIFETIME, $policy->keyLifetime);
        $this->assertSame(RotationPolicy::DEFAULT_ROTATION_BUFFER, $policy->rotationBuffer);
        $this->assertSame(RotationPolicy::DEFAULT_TIME_UNTIL_USE, $policy->timeUntilUse);
    }

    public function testFromEnvironmentReadsOverrides(): void
    {
        putenv('JWKS_KEY_LIFETIME=7200');
        putenv('JWKS_ROTATION_BUFFER=1800');
        putenv('JWKS_TIME_UNTIL_USE=300');

        $policy = RotationPolicy::fromEnvironment();

        $this->assertSame(7200, $policy->keyLifetime);
        $this->assertSame(1800, $policy->rotationBuffer);
        $this->assertSame(300, $policy->timeUntilUse);
    }

    public function testFromEnvironmentRejectsNonNumericValue(): void
    {
        putenv('JWKS_KEY_LIFETIME=soon');

        $this->expectException(InvalidArgumentException::class);

        RotationPolicy::fromEnvironment();
    }
}

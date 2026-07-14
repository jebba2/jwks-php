<?php

declare(strict_types=1);

namespace Jwks\Tests;

use Jwks\Cli;
use Jwks\KeyGenerator;
use Jwks\KeyStore;
use Jwks\RotationPolicy;
use PHPUnit\Framework\TestCase;

final class CliTest extends TestCase
{
    private string $directory;

    /** @var resource */
    private $out;

    /** @var resource */
    private $err;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/jwks-test-' . bin2hex(random_bytes(8));

        $out = fopen('php://memory', 'r+');
        $this->assertIsResource($out);
        $this->out = $out;

        $err = fopen('php://memory', 'r+');
        $this->assertIsResource($err);
        $this->err = $err;
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

    private function cli(?KeyGenerator $generator = null): Cli
    {
        $policy = new RotationPolicy(keyLifetime: 3000, rotationBuffer: 1000, timeUntilUse: 300);

        return new Cli(
            new KeyStore($this->directory),
            $policy,
            $generator ?? new KeyGenerator(),
            $this->out,
            $this->err,
        );
    }

    /**
     * @param resource $stream
     */
    private function streamContents($stream): string
    {
        rewind($stream);
        $contents = stream_get_contents($stream);
        $this->assertIsString($contents);

        return $contents;
    }

    public function testGenerateCreatesKeyAndPrintsKid(): void
    {
        $exitCode = $this->cli()->run(['jwks', 'generate']);

        $this->assertSame(0, $exitCode);

        $kids = new KeyStore($this->directory)->kids();
        $this->assertCount(1, $kids);
        $this->assertStringContainsString($kids[0], $this->streamContents($this->out));
    }

    public function testGenerateRejectsNonNumericBits(): void
    {
        $exitCode = $this->cli()->run(['jwks', 'generate', 'huge']);

        $this->assertSame(1, $exitCode);
        $this->assertSame([], new KeyStore($this->directory)->kids());
        $this->assertNotSame('', $this->streamContents($this->err));
    }

    public function testGenerateRejectsBitsBelow2048(): void
    {
        $exitCode = $this->cli()->run(['jwks', 'generate', '1024']);

        $this->assertSame(1, $exitCode);
        $this->assertSame([], new KeyStore($this->directory)->kids());
        $this->assertNotSame('', $this->streamContents($this->err));
    }

    public function testListPrintsOneKidPerLine(): void
    {
        $store = new KeyStore($this->directory);
        $firstKid = $store->add(new KeyGenerator()->generate());
        $secondKid = $store->add(new KeyGenerator()->generate());

        $exitCode = $this->cli()->run(['jwks', 'list']);

        $this->assertSame(0, $exitCode);
        $output = $this->streamContents($this->out);
        $this->assertStringContainsString($firstKid . "\n", $output);
        $this->assertStringContainsString($secondKid . "\n", $output);
    }

    public function testListMentionsWhenStoreIsEmpty(): void
    {
        $exitCode = $this->cli()->run(['jwks', 'list']);

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('No keys', $this->streamContents($this->out));
    }

    public function testRetireRemovesKey(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add(new KeyGenerator()->generate());

        $exitCode = $this->cli()->run(['jwks', 'retire', $kid]);

        $this->assertSame(0, $exitCode);
        $this->assertSame([], new KeyStore($this->directory)->kids());
    }

    public function testRetireUnknownKidFails(): void
    {
        $exitCode = $this->cli()->run(['jwks', 'retire', 'does-not-exist']);

        $this->assertSame(1, $exitCode);
        $this->assertNotSame('', $this->streamContents($this->err));
    }

    public function testRetireWithoutKidFails(): void
    {
        $exitCode = $this->cli()->run(['jwks', 'retire']);

        $this->assertSame(1, $exitCode);
        $this->assertNotSame('', $this->streamContents($this->err));
    }

    public function testShowPrintsKeySetJson(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add(new KeyGenerator()->generate());

        $exitCode = $this->cli()->run(['jwks', 'show']);

        $this->assertSame(0, $exitCode);
        $output = $this->streamContents($this->out);
        $this->assertJson($output);
        $this->assertStringContainsString($kid, $output);
    }

    public function testGenerateUsesConfiguredDefaultKeySize(): void
    {
        $exitCode = $this->cli(new KeyGenerator(3072))->run(['jwks', 'generate']);

        $this->assertSame(0, $exitCode);

        $store = new KeyStore($this->directory);
        $key = openssl_pkey_get_private($store->privatePem($store->kids()[0]));
        $this->assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        $this->assertNotFalse($details);
        $this->assertSame(3072, $details['bits']);
    }

    public function testGenerateStampsRotationMetadata(): void
    {
        $this->cli()->run(['jwks', 'generate']);

        $store = new KeyStore($this->directory);
        $metadata = $store->metadata($store->kids()[0]);

        $this->assertNotNull($metadata);
        $this->assertSame(3000 - 300, $metadata['expiresAt'] - $metadata['notBefore']);
    }

    public function testRotateOnEmptyStoreGeneratesFirstKey(): void
    {
        $exitCode = $this->cli()->run(['jwks', 'rotate']);

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('Generated key', $this->streamContents($this->out));
        $this->assertCount(1, new KeyStore($this->directory)->kids());
    }

    public function testRotateReportsWhenNothingNeedsDoing(): void
    {
        $cli = $this->cli();
        $cli->run(['jwks', 'generate']);

        $exitCode = $cli->run(['jwks', 'rotate']);

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('nothing to rotate', $this->streamContents($this->out));
    }

    public function testRotateSchedulesLegacyKeysForReplacement(): void
    {
        $legacyKid = new KeyStore($this->directory)->add(new KeyGenerator()->generate());

        $exitCode = $this->cli()->run(['jwks', 'rotate']);

        $this->assertSame(0, $exitCode);
        $output = $this->streamContents($this->out);
        $this->assertStringContainsString("Scheduled legacy key $legacyKid", $output);
        $this->assertStringContainsString('Generated key', $output);
        $this->assertCount(2, new KeyStore($this->directory)->kids());
    }

    public function testRotatePurgesLongExpiredKeys(): void
    {
        $store = new KeyStore($this->directory);
        $expiredKid = $store->add(new KeyGenerator()->generate(), notBefore: 0, expiresAt: 1000);

        $exitCode = $this->cli()->run(['jwks', 'rotate']);

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString("Purged expired key $expiredKid", $this->streamContents($this->out));
        $this->assertNotContains($expiredKid, new KeyStore($this->directory)->kids());
    }

    public function testSigningKeyPrintsKidAndPemPath(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add(new KeyGenerator()->generate(), notBefore: 0, expiresAt: PHP_INT_MAX);

        $exitCode = $this->cli()->run(['jwks', 'signing-key']);

        $this->assertSame(0, $exitCode);
        $this->assertSame(
            $kid . ' ' . $this->directory . '/' . $kid . '.pem' . "\n",
            $this->streamContents($this->out),
        );
    }

    public function testSigningKeyFailsWhenStoreIsEmpty(): void
    {
        $exitCode = $this->cli()->run(['jwks', 'signing-key']);

        $this->assertSame(1, $exitCode);
        $this->assertNotSame('', $this->streamContents($this->err));
    }

    public function testHelpPrintsUsage(): void
    {
        $exitCode = $this->cli()->run(['jwks', 'help']);

        $this->assertSame(0, $exitCode);
        $output = $this->streamContents($this->out);
        $this->assertStringContainsString('Usage', $output);
        $this->assertStringContainsString('rotate', $output);
        $this->assertStringContainsString('signing-key', $output);
    }

    public function testMissingCommandPrintsUsageAndFails(): void
    {
        $exitCode = $this->cli()->run(['jwks']);

        $this->assertSame(1, $exitCode);
        $this->assertStringContainsString('Usage', $this->streamContents($this->err));
    }

    public function testUnknownCommandPrintsUsageAndFails(): void
    {
        $exitCode = $this->cli()->run(['jwks', 'frobnicate']);

        $this->assertSame(1, $exitCode);
        $this->assertStringContainsString('Usage', $this->streamContents($this->err));
    }
}

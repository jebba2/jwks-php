<?php

declare(strict_types=1);

namespace Jwks\Tests;

use Jwks\Cli;
use Jwks\KeyGenerator;
use Jwks\KeyStore;
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

    private function cli(): Cli
    {
        return new Cli(new KeyStore($this->directory), $this->out, $this->err);
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

    public function testHelpPrintsUsage(): void
    {
        $exitCode = $this->cli()->run(['jwks', 'help']);

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('Usage', $this->streamContents($this->out));
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

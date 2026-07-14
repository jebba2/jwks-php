<?php

declare(strict_types=1);

namespace Jwks\Tests;

use Jwks\EnvFile;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class EnvFileTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/jwks-test-' . bin2hex(random_bytes(8));
        mkdir($this->directory, 0o700, true);
    }

    protected function tearDown(): void
    {
        putenv('JWKS_ENVTEST_ALPHA');
        putenv('JWKS_ENVTEST_BETA');

        if (is_dir($this->directory)) {
            $files = glob($this->directory . '/*');
            $this->assertIsArray($files);
            foreach ($files as $file) {
                unlink($file);
            }
            rmdir($this->directory);
        }
    }

    private function envFile(string $contents): string
    {
        $path = $this->directory . '/env';
        file_put_contents($path, $contents);

        return $path;
    }

    public function testLoadsVariablesIntoTheEnvironment(): void
    {
        EnvFile::load($this->envFile("JWKS_ENVTEST_ALPHA=3600\nJWKS_ENVTEST_BETA=hello\n"));

        $this->assertSame('3600', getenv('JWKS_ENVTEST_ALPHA'));
        $this->assertSame('hello', getenv('JWKS_ENVTEST_BETA'));
    }

    public function testRealEnvironmentVariablesWinOverTheFile(): void
    {
        putenv('JWKS_ENVTEST_ALPHA=from-environment');

        EnvFile::load($this->envFile("JWKS_ENVTEST_ALPHA=from-file\n"));

        $this->assertSame('from-environment', getenv('JWKS_ENVTEST_ALPHA'));
    }

    public function testSkipsCommentsAndBlankLines(): void
    {
        EnvFile::load($this->envFile("# a comment\n\n  \nJWKS_ENVTEST_ALPHA=1\n# another\n"));

        $this->assertSame('1', getenv('JWKS_ENVTEST_ALPHA'));
    }

    public function testStripsMatchingSurroundingQuotes(): void
    {
        EnvFile::load($this->envFile("JWKS_ENVTEST_ALPHA=\"/path/with space\"\nJWKS_ENVTEST_BETA='quoted'\n"));

        $this->assertSame('/path/with space', getenv('JWKS_ENVTEST_ALPHA'));
        $this->assertSame('quoted', getenv('JWKS_ENVTEST_BETA'));
    }

    public function testMissingFileIsANoOp(): void
    {
        EnvFile::load($this->directory . '/does-not-exist');

        $this->assertFalse(getenv('JWKS_ENVTEST_ALPHA'));
    }

    public function testMalformedLineIsRejectedWithItsLineNumber(): void
    {
        $path = $this->envFile("JWKS_ENVTEST_ALPHA=1\nnot a valid line\n");

        try {
            EnvFile::load($path);
            $this->fail('malformed env file must be rejected');
        } catch (RuntimeException $exception) {
            $this->assertStringContainsString('line 2', $exception->getMessage());
        }
    }
}

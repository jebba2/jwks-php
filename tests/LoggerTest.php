<?php

declare(strict_types=1);

namespace Jwks\Tests;

use Jwks\Logger;
use PHPUnit\Framework\TestCase;

final class LoggerTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/jwks-test-' . bin2hex(random_bytes(8));
    }

    protected function tearDown(): void
    {
        putenv('JWKS_LOG_FILE');

        // Innermost first: one test logs into a nested directory.
        foreach ([$this->directory . '/nested', $this->directory] as $directory) {
            if (!is_dir($directory)) {
                continue;
            }
            $files = glob($directory . '/*');
            $this->assertIsArray($files);
            foreach ($files as $file) {
                if (is_file($file)) {
                    unlink($file);
                }
            }
            rmdir($directory);
        }
    }

    private function logPath(): string
    {
        return $this->directory . '/jwks.log';
    }

    private function logContents(): string
    {
        $contents = file_get_contents($this->logPath());
        $this->assertNotFalse($contents);

        return $contents;
    }

    public function testInfoWritesTimestampedLine(): void
    {
        new Logger($this->logPath())->info('generated key abc');

        $line = $this->logContents();
        $this->assertStringContainsString(' INFO generated key abc', $line);
        $this->assertMatchesRegularExpression(
            '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00 INFO /',
            $line,
        );
    }

    public function testErrorWritesErrorLevelLine(): void
    {
        new Logger($this->logPath())->error('something broke');

        $this->assertStringContainsString(' ERROR something broke', $this->logContents());
    }

    public function testAppendsInsteadOfTruncating(): void
    {
        $logger = new Logger($this->logPath());
        $logger->info('first');
        $logger->info('second');

        $contents = $this->logContents();
        $this->assertStringContainsString('first', $contents);
        $this->assertStringContainsString('second', $contents);
        $this->assertSame(2, substr_count($contents, "\n"));
    }

    public function testCreatesMissingLogDirectory(): void
    {
        $path = $this->directory . '/nested/jwks.log';

        new Logger($path)->info('hello');

        $this->assertFileExists($path);
    }

    public function testFromEnvironmentHonorsLogFileOverride(): void
    {
        putenv('JWKS_LOG_FILE=' . $this->logPath());

        Logger::fromEnvironment()->info('via env');

        $this->assertStringContainsString('via env', $this->logContents());
    }

    public function testUnwritableLogFallsBackToErrorLogWithoutThrowing(): void
    {
        mkdir($this->directory, 0o700, true);
        $fallback = $this->directory . '/php-error-log';
        $previous = ini_set('error_log', $fallback);

        try {
            // The log path is a directory, so the write must fail.
            new Logger($this->directory)->error('undeliverable');
        } finally {
            ini_set('error_log', $previous === false ? '' : $previous);
        }

        $contents = file_get_contents($fallback);
        $this->assertNotFalse($contents);
        $this->assertStringContainsString('undeliverable', $contents);
    }
}

<?php

declare(strict_types=1);

namespace Jwks\Tests;

use Jwks\KeyStore;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end test: two real bin/jwks rotate processes racing on the same
 * empty key store must serialize and produce exactly one key.
 */
final class RotateLockTest extends TestCase
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
     * @return resource
     */
    private function startRotate()
    {
        $projectRoot = dirname(__DIR__);

        $process = proc_open(
            [PHP_BINARY, $projectRoot . '/bin/jwks', 'rotate'],
            [
                1 => ['file', '/dev/null', 'w'],
                2 => ['file', '/dev/null', 'w'],
            ],
            $pipes,
            $projectRoot,
            [
                'JWKS_KEYS_DIR' => $this->directory,
                'JWKS_LOG_FILE' => $this->directory . '/jwks.log',
            ],
        );
        $this->assertIsResource($process);

        return $process;
    }

    public function testSimultaneousRotatesGenerateExactlyOneKey(): void
    {
        $first = $this->startRotate();
        $second = $this->startRotate();

        $this->assertSame(0, proc_close($first));
        $this->assertSame(0, proc_close($second));

        $this->assertCount(1, new KeyStore($this->directory)->kids());
    }
}

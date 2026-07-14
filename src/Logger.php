<?php

declare(strict_types=1);

namespace Jwks;

/**
 * Appends timestamped activity and error lines to the service log file
 * (working/jwks.log by default, JWKS_LOG_FILE to override). A failed write
 * falls back to PHP's error_log instead of throwing, because losing a log
 * line must never take down the command or request being logged.
 */
final class Logger
{
    public function __construct(private readonly string $path)
    {
    }

    /**
     * Builds a logger for the path in the JWKS_LOG_FILE environment
     * variable, defaulting to working/jwks.log at the project root.
     */
    public static function fromEnvironment(): self
    {
        $path = getenv('JWKS_LOG_FILE');
        if (!is_string($path) || $path === '') {
            $path = dirname(__DIR__) . '/working/jwks.log';
        }

        return new self($path);
    }

    /**
     * Records a normal key-management activity.
     */
    public function info(string $message): void
    {
        $this->write('INFO', $message);
    }

    /**
     * Records a failure.
     */
    public function error(string $message): void
    {
        $this->write('ERROR', $message);
    }

    /**
     * Appends one timestamped line, creating the log directory on first use.
     */
    private function write(string $level, string $message): void
    {
        $line = gmdate('Y-m-d\TH:i:sP') . ' ' . $level . ' ' . $message . "\n";

        $directory = dirname($this->path);
        if (!is_dir($directory) && !@mkdir($directory, 0o700, true) && !is_dir($directory)) {
            error_log('jwks log unwritable (' . $this->path . '): ' . rtrim($line));

            return;
        }

        if (@file_put_contents($this->path, $line, FILE_APPEND | LOCK_EX) === false) {
            error_log('jwks log unwritable (' . $this->path . '): ' . rtrim($line));
        }
    }
}

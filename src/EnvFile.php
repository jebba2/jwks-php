<?php

declare(strict_types=1);

namespace Jwks;

use RuntimeException;

/**
 * Loads configuration from a .env file into the process environment.
 * Variables already present in the real environment win; the file only
 * fills gaps, so per-invocation overrides keep working. A missing file is
 * a no-op because the .env file is optional.
 */
final class EnvFile
{
    /**
     * KEY=VALUE with an uppercase environment-style name.
     */
    private const string LINE_PATTERN = '/^([A-Z][A-Z0-9_]*)=(.*)$/';

    public static function load(string $path): void
    {
        if (!is_file($path)) {
            return;
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            throw new RuntimeException("could not read env file $path");
        }

        foreach ($lines as $index => $rawLine) {
            $line = trim($rawLine);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            if (preg_match(self::LINE_PATTERN, $line, $matches) !== 1) {
                throw new RuntimeException(
                    sprintf('malformed line %d in env file %s', $index + 1, $path),
                );
            }

            $name = $matches[1];
            $value = self::withoutSurroundingQuotes(trim($matches[2]));

            if (getenv($name) === false) {
                putenv($name . '=' . $value);
            }
        }
    }

    /**
     * Strips one pair of matching single or double quotes, so values with
     * spaces can be written the way shells expect.
     */
    private static function withoutSurroundingQuotes(string $value): string
    {
        if (
            strlen($value) >= 2
            && ($value[0] === '"' || $value[0] === "'")
            && str_ends_with($value, $value[0])
        ) {
            return substr($value, 1, -1);
        }

        return $value;
    }
}

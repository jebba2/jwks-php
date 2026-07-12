<?php

declare(strict_types=1);

namespace Jwks;

use InvalidArgumentException;
use RuntimeException;

/**
 * Command-line interface for managing the signing keys behind the JWKS
 * endpoint. Streams are injected so commands are fully testable.
 */
final class Cli
{
    private const string USAGE = <<<'TEXT'
        Usage: jwks <command>

        Commands:
          generate [bits]   Generate a new RSA signing key (default 2048 bits) and add it to the key set
          list              List the kid of every key in the key set
          retire <kid>      Permanently remove a key from the key set
          show              Print the public JWKS document as JSON
          help              Show this help text

        Keys are stored in working/keys (override with the JWKS_KEYS_DIR environment variable).

        TEXT;

    /** @var resource */
    private $out;

    /** @var resource */
    private $err;

    /**
     * @param resource $out stream for normal command output
     * @param resource $err stream for error messages
     */
    public function __construct(private readonly KeyStore $store, $out, $err)
    {
        $this->out = $out;
        $this->err = $err;
    }

    /**
     * Runs one CLI invocation and returns the process exit code.
     *
     * @param list<string> $argv full argument vector including the script name
     */
    public function run(array $argv): int
    {
        $command = $argv[1] ?? null;

        return match ($command) {
            'generate' => $this->generate($argv[2] ?? null),
            'list' => $this->listKeys(),
            'retire' => $this->retire($argv[2] ?? null),
            'show' => $this->show(),
            'help', '--help', '-h' => $this->printUsage($this->out, 0),
            default => $this->printUsage($this->err, 1),
        };
    }

    /**
     * Generates a new signing key and prints its kid.
     */
    private function generate(?string $bitsArgument): int
    {
        if ($bitsArgument !== null && !ctype_digit($bitsArgument)) {
            fwrite($this->err, "Error: bits must be a positive integer, got \"$bitsArgument\"\n");

            return 1;
        }

        try {
            $pem = $bitsArgument === null
                ? new KeyGenerator()->generate()
                : new KeyGenerator()->generate((int) $bitsArgument);
            $kid = $this->store->add($pem);
        } catch (InvalidArgumentException | RuntimeException $exception) {
            fwrite($this->err, 'Error: ' . $exception->getMessage() . "\n");

            return 1;
        }

        fwrite($this->out, "Generated key $kid\n");

        return 0;
    }

    /**
     * Prints the kid of every stored key, one per line.
     */
    private function listKeys(): int
    {
        $kids = $this->store->kids();
        if ($kids === []) {
            fwrite($this->out, "No keys in the key set. Run \"jwks generate\" to create one.\n");

            return 0;
        }

        foreach ($kids as $kid) {
            fwrite($this->out, $kid . "\n");
        }

        return 0;
    }

    /**
     * Removes a key from the store.
     */
    private function retire(?string $kid): int
    {
        if ($kid === null) {
            fwrite($this->err, "Error: retire requires a kid. Run \"jwks list\" to see stored keys.\n");

            return 1;
        }

        try {
            $this->store->retire($kid);
        } catch (InvalidArgumentException | RuntimeException $exception) {
            fwrite($this->err, 'Error: ' . $exception->getMessage() . "\n");

            return 1;
        }

        fwrite($this->out, "Retired key $kid\n");

        return 0;
    }

    /**
     * Prints the public JWKS document.
     */
    private function show(): int
    {
        fwrite($this->out, new JwksBuilder($this->store)->toJson() . "\n");

        return 0;
    }

    /**
     * Prints usage text to the given stream and returns the exit code.
     *
     * @param resource $stream
     */
    private function printUsage($stream, int $exitCode): int
    {
        fwrite($stream, self::USAGE);

        return $exitCode;
    }
}

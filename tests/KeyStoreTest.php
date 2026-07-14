<?php

declare(strict_types=1);

namespace Jwks\Tests;

use InvalidArgumentException;
use Jwks\KeyGenerator;
use Jwks\KeyStore;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class KeyStoreTest extends TestCase
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

    private function fixturePem(): string
    {
        $pem = file_get_contents(__DIR__ . '/fixtures/test-key.pem');
        $this->assertNotFalse($pem);

        return $pem;
    }

    public function testCreatesMissingDirectoryWithOwnerOnlyPermissions(): void
    {
        new KeyStore($this->directory);

        $this->assertDirectoryExists($this->directory);
        $this->assertSame(0o700, fileperms($this->directory) & 0o777);
    }

    public function testAddStoresKeyAndReturnsKid(): void
    {
        $store = new KeyStore($this->directory);

        $kid = $store->add($this->fixturePem());

        $this->assertSame('gXI7LN05n7GL-OahEsEhZpif_kKsenrycOQFDVA_8Gc', $kid);
        $this->assertFileExists($this->directory . '/' . $kid . '.pem');
    }

    public function testStoredKeyFileIsOwnerReadWriteOnly(): void
    {
        $store = new KeyStore($this->directory);

        $kid = $store->add($this->fixturePem());

        $this->assertSame(0o600, fileperms($this->directory . '/' . $kid . '.pem') & 0o777);
    }

    public function testAddIsIdempotentForTheSameKey(): void
    {
        $store = new KeyStore($this->directory);

        $store->add($this->fixturePem());
        $store->add($this->fixturePem());

        $this->assertCount(1, $store->kids());
    }

    public function testAddRejectsInvalidPem(): void
    {
        $store = new KeyStore($this->directory);

        $this->expectException(InvalidArgumentException::class);

        $store->add('not a pem');
    }

    public function testKidsListsAllStoredKeysSorted(): void
    {
        $store = new KeyStore($this->directory);
        $first = $store->add($this->fixturePem());
        $second = $store->add(new KeyGenerator()->generate());

        $kids = $store->kids();

        $expected = [$first, $second];
        sort($expected);
        $this->assertSame($expected, $kids);
    }

    public function testKidsIsEmptyForNewStore(): void
    {
        $this->assertSame([], new KeyStore($this->directory)->kids());
    }

    public function testPrivatePemReturnsStoredKey(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add($this->fixturePem());

        $this->assertSame($this->fixturePem(), $store->privatePem($kid));
    }

    public function testPrivatePemRejectsUnknownKid(): void
    {
        $store = new KeyStore($this->directory);

        $this->expectException(RuntimeException::class);

        $store->privatePem('does-not-exist');
    }

    public function testPrivatePemRejectsKidWithPathCharacters(): void
    {
        $store = new KeyStore($this->directory);

        $this->expectException(InvalidArgumentException::class);

        $store->privatePem('../etc/passwd');
    }

    public function testRetireRemovesKey(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add($this->fixturePem());

        $store->retire($kid);

        $this->assertSame([], $store->kids());
        $this->assertFileDoesNotExist($this->directory . '/' . $kid . '.pem');
    }

    public function testRetireRejectsUnknownKid(): void
    {
        $store = new KeyStore($this->directory);

        $this->expectException(RuntimeException::class);

        $store->retire('does-not-exist');
    }

    public function testAddWithLifecycleStampsWritesMetadata(): void
    {
        $store = new KeyStore($this->directory);

        $kid = $store->add($this->fixturePem(), notBefore: 1000, expiresAt: 2000);

        $this->assertSame(['notBefore' => 1000, 'expiresAt' => 2000], $store->metadata($kid));
        $this->assertSame(0o600, fileperms($this->directory . '/' . $kid . '.json') & 0o777);
    }

    public function testAddRejectsPartialLifecycleStamps(): void
    {
        $store = new KeyStore($this->directory);

        $this->expectException(InvalidArgumentException::class);

        $store->add($this->fixturePem(), notBefore: 1000);
    }

    public function testMetadataIsNullForUnstampedKey(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add($this->fixturePem());

        $this->assertNull($store->metadata($kid));
    }

    public function testMetadataRejectsUnknownKid(): void
    {
        $store = new KeyStore($this->directory);

        $this->expectException(RuntimeException::class);

        $store->metadata('does-not-exist');
    }

    public function testStampAddsMetadataToExistingKey(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add($this->fixturePem());

        $store->stamp($kid, notBefore: 1000, expiresAt: 2000);

        $this->assertSame(['notBefore' => 1000, 'expiresAt' => 2000], $store->metadata($kid));
    }

    public function testStampRejectsUnknownKid(): void
    {
        $store = new KeyStore($this->directory);

        $this->expectException(RuntimeException::class);

        $store->stamp('does-not-exist', notBefore: 1000, expiresAt: 2000);
    }

    public function testPemPathReturnsTheKeyFileLocation(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add($this->fixturePem());

        $this->assertSame($this->directory . '/' . $kid . '.pem', $store->pemPath($kid));
    }

    public function testPemPathRejectsUnknownKid(): void
    {
        $store = new KeyStore($this->directory);

        $this->expectException(RuntimeException::class);

        $store->pemPath('does-not-exist');
    }

    public function testRetireRemovesMetadataFile(): void
    {
        $store = new KeyStore($this->directory);
        $kid = $store->add($this->fixturePem(), notBefore: 1000, expiresAt: 2000);

        $store->retire($kid);

        $this->assertFileDoesNotExist($this->directory . '/' . $kid . '.json');
        $this->assertSame([], $store->kids());
    }
}

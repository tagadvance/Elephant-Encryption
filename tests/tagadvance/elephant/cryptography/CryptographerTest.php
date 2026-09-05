<?php

namespace tagadvance\elephant\cryptography;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SplFileInfo;
use tagadvance\elephant\cryptography\distinguishedname\ArrayBuilder;

class CryptographerTest extends TestCase
{
    private const KEY = __DIR__ . '/../../../resources/elephant.key';

    private PrivateKey $privateKey;

    private PublicKey $publicKey;

    public function setUp(): void
    {
        $this->privateKey = PrivateKey::createFromFile(new SplFileInfo(self::KEY));

        $csr = CertificateSigningRequest::newCertificateSigningRequest(new ArrayBuilder([]), $this->privateKey);
        $certificate = $csr->sign($this->privateKey);
        $this->publicKey = PublicKey::createFromCertificate($certificate);
    }

    /**
     * @return array<string, array{int}>
     */
    public static function sizeProvider(): array
    {
        $blockSize = PrivateKey::createFromFile(new SplFileInfo(self::KEY))->calculateDecryptSize();

        return [
            'empty' => [0],
            'one byte' => [1],
            'one byte below a whole block' => [$blockSize - 1],
            'exactly one block' => [$blockSize],
            'one byte above a whole block' => [$blockSize + 1],
            'several blocks' => [3 * $blockSize],
        ];
    }

    #[DataProvider('sizeProvider')]
    public function testPublicEncryptPrivateDecryptRoundTrip(int $size): void
    {
        $encrypter = new PublicKeyCryptographer($this->publicKey);
        $decrypter = new PrivateKeyCryptographer($this->privateKey);

        $data = str_repeat('a', $size);
        $this->assertSame($data, $decrypter->decrypt($encrypter->encrypt($data)));
    }

    #[DataProvider('sizeProvider')]
    public function testPrivateEncryptPublicDecryptRoundTrip(int $size): void
    {
        $encrypter = new PrivateKeyCryptographer($this->privateKey);
        $decrypter = new PublicKeyCryptographer($this->publicKey);

        $data = str_repeat('a', $size);
        $this->assertSame($data, $decrypter->decrypt($encrypter->encrypt($data)));
    }

    public function testPublicEncryptRoundTripAtOaepBoundary(): void
    {
        $encrypter = new PublicKeyCryptographer($this->publicKey);
        $decrypter = new PrivateKeyCryptographer($this->privateKey);

        $maximum = $this->privateKey->calculateDecryptSize() - OpenSSL::OAEP_PADDING;
        foreach ([$maximum - 1, $maximum, $maximum + 1] as $size) {
            $data = str_repeat('a', $size);
            $this->assertSame($data, $decrypter->decrypt($encrypter->encrypt($data)), "size $size");
        }
    }

    public function testPublicEncryptRoundTripOfFalsyData(): void
    {
        $encrypter = new PublicKeyCryptographer($this->publicKey);
        $decrypter = new PrivateKeyCryptographer($this->privateKey);

        $maximum = $this->privateKey->calculateDecryptSize() - OpenSSL::OAEP_PADDING;
        foreach (['0', str_repeat('a', $maximum) . '0'] as $data) {
            $this->assertSame($data, $decrypter->decrypt($encrypter->encrypt($data)));
        }
    }

    public function testPrivateEncryptRoundTripOfFalsyData(): void
    {
        $encrypter = new PrivateKeyCryptographer($this->privateKey);
        $decrypter = new PublicKeyCryptographer($this->publicKey);

        $maximum = $this->privateKey->calculateEncryptSize();
        foreach (['0', str_repeat('a', $maximum) . '0'] as $data) {
            $this->assertSame($data, $decrypter->decrypt($encrypter->encrypt($data)));
        }
    }

    public function testPrivateEncryptRoundTripAtPkcs1Boundary(): void
    {
        $encrypter = new PrivateKeyCryptographer($this->privateKey);
        $decrypter = new PublicKeyCryptographer($this->publicKey);

        $maximum = $this->privateKey->calculateEncryptSize();
        foreach ([$maximum - 1, $maximum, $maximum + 1] as $size) {
            $data = str_repeat('a', $size);
            $this->assertSame($data, $decrypter->decrypt($encrypter->encrypt($data)), "size $size");
        }
    }
}

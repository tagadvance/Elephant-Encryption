<?php

namespace tagadvance\elephant\cryptography;

use PHPUnit\Framework\TestCase;
use SplFileInfo;
use tagadvance\elephant\cryptography\distinguishedname\ArrayBuilder;

class PublicKeyTest extends TestCase
{
    public function testCreateFromCertificate()
    {
        $builder = new ArrayBuilder([]);

        $path = __DIR__ . '/../../../resources/elephant.key';
        $file = new SplFileInfo($path);
        $privateKey = PrivateKey::createFromFile($file);

        $csr = CertificateSigningRequest::newCertificateSigningRequest($builder, $privateKey);
        $certificate = $csr->sign($privateKey);

        $publicKey = PublicKey::createFromCertificate($certificate);
        $this->assertInstanceOf(PublicKey::class, $publicKey);
    }

    public function testCreateFromPem()
    {
        $path = __DIR__ . '/../../../resources/elephant.key';
        $privateKey = PrivateKey::createFromFile(new SplFileInfo($path));
        $pem = $privateKey->getDetails()['key'];

        $publicKey = PublicKey::createFromPem($pem);

        // The key is usable, not merely constructed.
        $data = 'attack at dawn';
        $encrypter = new PublicKeyCryptographer($publicKey);
        $decrypter = new PrivateKeyCryptographer($privateKey);
        $this->assertSame($data, $decrypter->decrypt($encrypter->encrypt($data)));
    }

    public function testCreateFromPemRejectsGarbage()
    {
        $this->expectException(CryptographyException::class);
        $this->expectExceptionMessage('could not read public key');
        PublicKey::createFromPem('not a key');
    }

    public function testConstructorIsPrivate()
    {
        $constructor = (new \ReflectionClass(PublicKey::class))->getConstructor();

        $this->assertTrue($constructor->isPrivate());
    }

    public function testCalculateEncryptSize()
    {
        $publicKey = $this->newPublicKey();

        $expected = $publicKey->calculateDecryptSize() - OpenSSL::OAEP_PADDING;
        $this->assertSame($expected, $publicKey->calculateEncryptSize());
    }

    public function testCalculateDecryptSize()
    {
        $publicKey = $this->newPublicKey();

        $bits = $publicKey->getDetails()['bits'];
        $this->assertSame($bits / 8, $publicKey->calculateDecryptSize());
    }

    public function testCalculateDecryptSizeRoundsUpToWholeBytes()
    {
        $key = $this->createPartialMock(PublicKey::class, ['getDetails']);
        $key->expects($this->once())->method('getDetails')->willReturn(['bits' => 2049]);

        $this->assertSame(257, $key->calculateDecryptSize());
    }

    private function newPublicKey(): PublicKey
    {
        $builder = new ArrayBuilder([]);

        $path = __DIR__ . '/../../../resources/elephant.key';
        $file = new SplFileInfo($path);
        $privateKey = PrivateKey::createFromFile($file);

        $csr = CertificateSigningRequest::newCertificateSigningRequest($builder, $privateKey);
        $certificate = $csr->sign($privateKey);

        return PublicKey::createFromCertificate($certificate);
    }

}

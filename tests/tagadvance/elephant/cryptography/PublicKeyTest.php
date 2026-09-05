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

    public function testCalculateEncryptSize()
    {
        $publicKey = $this->newPublicKey();

        $expected = $publicKey->calculateDecryptSize() - OpenSSL::PADDING;
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

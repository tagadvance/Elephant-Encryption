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
        $this->assertTrue(true);
    }

    public function testCalculateEncryptSize()
    {
        $this->markTestSkipped();
    }

    public function calculateDecryptSize()
    {
        $this->markTestSkipped();
    }

}

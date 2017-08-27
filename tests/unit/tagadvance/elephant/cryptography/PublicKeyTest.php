<?php

namespace tagadvance\elephant\cryptography;

use PHPUnit\Framework\TestCase;

class PublicKeyTest extends TestCase {

    function testCreateFromCertificate() {
        $builder = $this->getMockBuilder(ArrayBuilder::class)
                ->disableOriginalConstructor()
                ->getMock();
        $builder->method('build')->willReturn([]);
        
        $path = __DIR__ . '/../../../../resources/elephant.key';
        $file = new \SplFileInfo($path);
        $privateKey = PrivateKey::createFromFile($file);
        
        $csr = CertificateSigningRequest::newCertificateSigningRequest($builder, $privateKey);
        $certificate = $csr->sign($privateKey);
        
        $publicKey = PublicKey::createFromCertificate($certificate);
        $this->assertTrue(true);
        
        $certificate->close();
        $privateKey->close();
    }

    function testCalculateEncryptSize() {
        $this->markTestSkipped();
    }

    function calculateDecryptSize() {
        $this->markTestSkipped();
    }

}
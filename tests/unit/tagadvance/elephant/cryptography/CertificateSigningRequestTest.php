<?php

namespace tagadvance\elephant\cryptography;

use PHPUnit\Framework\TestCase;

class CertificateSigningRequestTest extends TestCase {

    private $privateKey;

    private $csr;

    function setUp() {
        $builder = $this->getMockBuilder(ArrayBuilder::class)
                ->disableOriginalConstructor()
                ->getMock();
        $builder->method('build')->willReturn([]);
        
        $path = __DIR__ . '/../../../../resources/elephant.key';
        $file = new \SplFileInfo($path);
        $this->privateKey = PrivateKey::createFromFile($file);
        
        $this->csr = CertificateSigningRequest::newCertificateSigningRequest($builder, $this->privateKey);
    }

    function testNewCertificateSigningRequest() {
        $this->csr->sign($this->privateKey);
        $this->assertTrue(true);
    }

    function testSign() {
        $this->csr->sign($this->privateKey);
        $this->assertTrue(true);
    }

    /**
     * @expectedException tagadvance\elephant\cryptography\CryptographyException
     */
    function testSignWithBogusPrivateKey() {
        $key = $this->getMockBuilder(PrivateKey::class)
            ->disableOriginalConstructor()
            ->getMock();
        $this->csr->sign($key);
    }

    function testSignedExport() {
        $this->csr->sign($this->privateKey);
        $this->assertStringStartsWith($prefix = '-----BEGIN CERTIFICATE REQUEST-----', $this->csr->export());
    }

    function testSignedExportHumanReadable() {
        $this->csr->sign($this->privateKey);
        
        $this->assertStringStartsWith($prefix = 'Certificate Request:', $this->csr->export(true));
    }

    function testUnsignedExport() {
        $this->assertStringStartsWith($prefix = '-----BEGIN CERTIFICATE REQUEST-----', $this->csr->export());
    }

    function testUnsignedExportHumanReadable() {
        $this->assertStringStartsWith($prefix = 'Certificate Request:', $this->csr->export(true));
    }

    function testExportToFile() {
        $path = '/tmp/elephant.csr';
        $file = new \SplFileInfo($path);
        $this->csr->exportToFile($file);
        
        $export = file_get_contents($path);
        $this->assertStringStartsWith($prefix = '-----BEGIN CERTIFICATE REQUEST-----', $export);
        $this->assertStringEndsWith($prefix = '-----END CERTIFICATE REQUEST-----', trim($export));
    }

    function testExportToFileHumanReadable() {
        $path = '/tmp/elephant-human-readable.csr';
        $file = new \SplFileInfo($path);
        $this->csr->exportToFile($file);
        
        $export = file_get_contents($path);
        $this->assertStringStartsWith($prefix = '-----BEGIN CERTIFICATE REQUEST-----', $export);
        $this->assertStringEndsWith($prefix = '-----END CERTIFICATE REQUEST-----', trim($export));
    }

    function tearDown() {
        $this->privateKey->close();
    }

}
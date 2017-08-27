<?php

namespace tagadvance\elephant\cryptography;

use PHPUnit\Framework\TestCase;

class CertificateTest extends TestCase {

    /**
     *
     * @var PrivateKey
     */
    private $privateKey;

    /**
     *
     * @var Certificate
     */
    private $certificate;

    function setUp() {
        $builder = $this->getMockBuilder(ArrayBuilder::class)
                ->disableOriginalConstructor()
                ->getMock();
        $builder->method('build')->willReturn([]);
        
        $path = __DIR__ . '/../../../../resources/elephant.key';
        $file = new \SplFileInfo($path);
        $this->privateKey = PrivateKey::createFromFile($file);
        
        $csr = CertificateSigningRequest::newCertificateSigningRequest($builder, $this->privateKey);
        $this->certificate = $csr->sign($this->privateKey);
    }

    function testCreateFromFile() {
        $path = __DIR__ . '/../../../../resources/elephant.cert';
        $file = new \SplFileInfo($path);
        $certificate = Certificate::createFromFile($file);
        $this->assertTrue(true);
        $certificate->close();
    }

    function testExport() {
        $export = $this->certificate->export();
        $this->assertStringStartsWith($prefix = '-----BEGIN CERTIFICATE-----', $export);
        $this->assertStringEndsWith($prefix = '-----END CERTIFICATE-----', trim($export));
    }

    function testExportHumanReadable() {
        $export = $this->certificate->export(true);
        $this->assertStringStartsWith($prefix = 'Certificate:', $export);
        $this->assertStringEndsWith($prefix = '-----END CERTIFICATE-----', trim($export));
    }

    function testExportToFile() {
        $path = '/tmp/elephant.csr';
        $file = new \SplFileInfo($path);
        $this->certificate->exportToFile($file);
        
        $export = file_get_contents($path);
        $this->assertStringStartsWith($prefix = '-----BEGIN CERTIFICATE-----', $export);
        $this->assertStringEndsWith($prefix = '-----END CERTIFICATE-----', trim($export));
    }

    function testExportToFileHumanReadable() {
        $path = '/tmp/elephant-human-readable.csr';
        $file = new \SplFileInfo($path);
        $this->certificate->exportToFile($file, true);
        
        $export = file_get_contents($path);
        $this->assertStringStartsWith($prefix = 'Certificate:', $export);
        $this->assertStringEndsWith($prefix = '-----END CERTIFICATE-----', trim($export));
    }

    function tearDown() {
        $this->certificate->close();
        $this->privateKey->close();
    }

}
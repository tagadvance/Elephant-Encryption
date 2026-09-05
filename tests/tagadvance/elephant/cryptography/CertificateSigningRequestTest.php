<?php

namespace tagadvance\elephant\cryptography;

use PHPUnit\Framework\TestCase;
use SplFileInfo;
use tagadvance\elephant\cryptography\distinguishedname\ArrayBuilder;

class CertificateSigningRequestTest extends TestCase
{
    private PrivateKey $privateKey;

    private CertificateSigningRequest $csr;

    public function setUp(): void
    {
        $builder = new ArrayBuilder([]);

        $path = __DIR__ . '/../../../resources/elephant.key';
        $file = new SplFileInfo($path);
        $this->privateKey = PrivateKey::createFromFile($file);

        $this->csr = CertificateSigningRequest::newCertificateSigningRequest($builder, $this->privateKey);
    }

    public function testNewCertificateSigningRequest()
    {
        $this->assertInstanceOf(Certificate::class, $this->csr->sign($this->privateKey));
    }

    public function testSign()
    {
        $this->assertInstanceOf(Certificate::class, $this->csr->sign($this->privateKey));
    }

    public function testSignWithBogusPrivateKey()
    {
        $this->expectException(CryptographyException::class);

        $key = $this->createStub(PrivateKey::class);
        $this->csr->sign($key);
    }

    public function testSignedExport()
    {
        $this->csr->sign($this->privateKey);
        $this->assertStringStartsWith($prefix = '-----BEGIN CERTIFICATE REQUEST-----', $this->csr->export());
    }

    public function testSignedExportHumanReadable()
    {
        $this->csr->sign($this->privateKey);

        $this->assertStringStartsWith($prefix = 'Certificate Request:', $this->csr->export(true));
    }

    public function testUnsignedExport()
    {
        $this->assertStringStartsWith($prefix = '-----BEGIN CERTIFICATE REQUEST-----', $this->csr->export());
    }

    public function testUnsignedExportHumanReadable()
    {
        $this->assertStringStartsWith($prefix = 'Certificate Request:', $this->csr->export(true));
    }

    public function testExportToFile()
    {
        $path = '/tmp/elephant.csr';
        $file = new SplFileInfo($path);
        $this->csr->exportToFile($file);

        $export = file_get_contents($path);
        $this->assertStringStartsWith($prefix = '-----BEGIN CERTIFICATE REQUEST-----', $export);
        $this->assertStringEndsWith($prefix = '-----END CERTIFICATE REQUEST-----', trim($export));
    }

    public function testExportToFileHumanReadable()
    {
        $path = '/tmp/elephant-human-readable.csr';
        $file = new SplFileInfo($path);
        $this->csr->exportToFile($file);

        $export = file_get_contents($path);
        $this->assertStringStartsWith($prefix = '-----BEGIN CERTIFICATE REQUEST-----', $export);
        $this->assertStringEndsWith($prefix = '-----END CERTIFICATE REQUEST-----', trim($export));
    }

}

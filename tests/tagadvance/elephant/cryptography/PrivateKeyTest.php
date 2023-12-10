<?php

namespace tagadvance\elephant\cryptography;

use PHPUnit\Framework\TestCase;
use SplFileInfo;

class PrivateKeyTest extends TestCase {

    function testNewPrivateKey() {
        $configuration = ConfigurationBuilder::builder();
        $privateKey = PrivateKey::newPrivateKey($configuration);
        $this->assertTrue(true);
    }

    function testNewPrivateKeyWithBogusConfigurationThrowsCryptographyException() {
        $this->expectException(CryptographyException::class);

        $configuration = $this->getMockBuilder(ConfigurationBuilder::class)->getMock();
        $configuration->method('build')->willReturn([
                'private_key_bits' => 0
        ]);
        $privateKey = PrivateKey::newPrivateKey($configuration);
        $this->assertTrue(true);
    }

    function testCreateFromFile() {
        $path = __DIR__ . '/../../../resources/elephant.key';
        $file = new SplFileInfo($path);
        $key = PrivateKey::createFromFile($file);
        $this->assertTrue(true);
    }

    function testCreateFromFileWithPassword() {
        // TODO
        $this->markTestSkipped();
    }

    function testCreateFromFileThrowsCryptographyException() {
        $this->expectException(CryptographyException::class);

        $path = '/dev/null';
        $file = new SplFileInfo($path);
        PrivateKey::createFromFile($file);
    }

    function testGetDetails() {
        $path = __DIR__ . '/../../../resources/elephant.key';
        $file = new SplFileInfo($path);
        $key = PrivateKey::createFromFile($file);
        $details = $key->getDetails();
        $this->assertTrue(true);
    }

    function testExport() {
        $path = __DIR__ . '/../../../resources/elephant.key';
        $file = new SplFileInfo($path);
        $key = PrivateKey::createFromFile($file);

        $path = '/tmp/elephant.key';
        $file = new SplFileInfo($path);
        $export = $key->export($file);

        $this->assertStringStartsWith($prefix = '-----BEGIN', $export);
        $this->assertStringEndsWith($prefix = 'PRIVATE KEY-----', trim($export));
    }

    function testExportToFile() {
        $path = __DIR__ . '/../../../resources/elephant.key';
        $file = new SplFileInfo($path);
        $key = PrivateKey::createFromFile($file);

        $path = '/tmp/elephant.key';
        $file = new SplFileInfo($path);
        $key->exportToFile($file, $password = null, $configuration = null);

        $export = file_get_contents($path);
        $this->assertStringStartsWith($prefix = '-----BEGIN', $export);
        $this->assertStringEndsWith($prefix = 'PRIVATE KEY-----', trim($export));
    }

}

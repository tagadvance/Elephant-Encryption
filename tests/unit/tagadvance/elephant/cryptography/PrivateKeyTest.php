<?php

namespace tagadvance\elephant\cryptography;

use PHPUnit\Framework\TestCase;
use tagadvance\gilligan\security\Hash;

class PrivateKeyTest extends TestCase {

    function testNewPrivateKey() {
        $configuration = ConfigurationBuilder::builder()
                ->setConfigurationFile(ConfigurationBuilder::CONFIG_DEBIAN)
                ->setDigestAlgorithm(Hash::ALGORITHM_SHA512)
                ->setX509Extensions('v3_ca')
                ->setRequiredExtensions('v3_req')
                ->setPrivateKeyBits(4096)
                ->setPrivateKeyType();
        $privateKey = PrivateKey::newPrivateKey($configuration);
        $this->assertTrue(true);
    }

    /**
     * @expectedException tagadvance\elephant\cryptography\CryptographyException
     */
    function testNewPrivateKeyWithBogusConfigurationThrowsCryptographyException() {
        $configuration = ConfigurationBuilder::builder()
                ->setConfigurationFile(ConfigurationBuilder::CONFIG_DEBIAN)
                ->setDigestAlgorithm(Hash::ALGORITHM_SHA512)
                ->setX509Extensions('foo')
                ->setRequiredExtensions('foo')
                ->setPrivateKeyBits(4096)
                ->setPrivateKeyType();
        $privateKey = PrivateKey::newPrivateKey($configuration);
        $this->assertTrue(true);
    }

    function testCreateFromFile() {
        $path = __DIR__ . '/../../../../resources/elephant.key';
        $file = new \SplFileInfo($path);
        try {
            $key = PrivateKey::createFromFile($file);
            $this->assertTrue(true);
        } finally {
            $key->close();
        }
    }

    function testCreateFromFileWithPassword() {
        // TODO
        $this->markTestSkipped();
    }

    /**
     * @expectedException tagadvance\elephant\cryptography\CryptographyException
     */
    function testCreateFromFileThrowsCryptographyException() {
        $path = '/dev/null';
        $file = new \SplFileInfo($path);
        PrivateKey::createFromFile($file);
    }

    function testGetDetails() {
        $path = __DIR__ . '/../../../../resources/elephant.key';
        $file = new \SplFileInfo($path);
        try {
            $key = PrivateKey::createFromFile($file);
            $details = $key->getDetails();
            $this->assertTrue(true);
        } finally {
            $key->close();
        }
    }

    function testExport() {
        $path = __DIR__ . '/../../../../resources/elephant.key';
        $file = new \SplFileInfo($path);
        try {
            $key = PrivateKey::createFromFile($file);
            
            $path = '/tmp/elephant.key';
            $file = new \SplFileInfo($path);
            $export = $key->export($file);
            
            $this->assertStringStartsWith($prefix = '-----BEGIN', $export);
            $this->assertStringEndsWith($prefix = 'PRIVATE KEY-----', trim($export));
        } finally {
            $key->close();
        }
    }

    function testExportToFile() {
        $path = __DIR__ . '/../../../../resources/elephant.key';
        $file = new \SplFileInfo($path);
        try {
            $key = PrivateKey::createFromFile($file);
            
            $path = '/tmp/elephant.key';
            $file = new \SplFileInfo($path);
            $key->exportToFile($file, $password = null, $configuration = null);
            
            $export = file_get_contents($path);
            $this->assertStringStartsWith($prefix = '-----BEGIN', $export);
            $this->assertStringEndsWith($prefix = 'PRIVATE KEY-----', trim($export));
        } finally {
            $key->close();
        }
    }

}
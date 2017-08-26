<?php

namespace tagadvance\elephant\cryptography;

use PHPUnit\Framework\TestCase;
use tagadvance\gilligan\security\Hash;

class ConfigurationBuilderTest extends TestCase {
	
	function testBuilder() {
		$expected = [ 
				'config' => ConfigurationBuilder::CONFIG_DEBIAN,
				'digest_alg' => Hash::ALGORITHM_SHA512,
				'x509_extensions' => 'v3_ca',
				'req_extensions' => 'v3_req',
				'private_key_bits' => 4096,
				'private_key_type' => 0,
				'encrypt_key' => true,
				'encrypt_key_cipher' => OPENSSL_CIPHER_AES_256_CBC 
		];
		$configuration = ConfigurationBuilder::builder()
				->setConfigurationFile(ConfigurationBuilder::CONFIG_DEBIAN)
				->setDigestAlgorithm(Hash::ALGORITHM_SHA512)
				->setX509Extensions('v3_ca')
				->setRequiredExtensions('v3_req')
				->setPrivateKeyBits(4096)
				->setPrivateKeyType()
				->encryptKey()
				->withCypher(OPENSSL_CIPHER_AES_256_CBC)
				->build();
		$this->assertEquals($expected, $configuration);
	}
	
}
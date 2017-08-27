<?php

namespace tagadvance\elephant\cryptography;

use PHPUnit\Framework\TestCase;
use tagadvance\gilligan\security\Hash;

class CryptographyTest extends TestCase {

    function test() {
        $data = <<<DATA
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad
minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit
in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia
deserunt mollit anim id est laborum.
DATA;
        
        $configuration = ConfigurationBuilder::builder()
                ->setConfigurationFile(ConfigurationBuilder::CONFIG_DEBIAN)
                ->setDigestAlgorithm(Hash::ALGORITHM_SHA512)
                ->setX509Extensions('v3_ca')
                ->setRequiredExtensions('v3_req')
                ->setPrivateKeyBits(4096)
                ->setPrivateKeyType();
        $privateKey = PrivateKey::newPrivateKey($configuration);
        try {
            $dn = DistinguishedNameBuilder::builder()
                    ->setCountryName('US')
                    ->setStateOrProvinceName('OR')
                    ->setLocality('Crater Lake')
                    ->setOrganizationName('Acme Corporation')
                    ->setOrganizationUnitName('.')
                    ->setCommonName('Wile E Coyote')
                    ->setEmailAddress('w.coyote@acme.com');
            $csr = CertificateSigningRequest::newCertificateSigningRequest($dn, $privateKey);
            $certificate = $csr->sign($privateKey);
            try {
                $publicKey = PublicKey::createFromCertificate($certificate);
                
                $privateKeyCryptographer = Base64Cryptographer::create(new PrivateKeyCryptographer($privateKey));
                $publicKeyCryptographer = Base64Cryptographer::create(new PublicKeyCryptographer($privateKey, $publicKey));
                
                $encryptedData = $privateKeyCryptographer->encrypt($data);
                $decryptedData = $publicKeyCryptographer->decrypt($encryptedData);
                $this->assertEquals($expected = $data, $actual = $decryptedData);
                
                $encryptedData = $publicKeyCryptographer->encrypt($data);
                $decryptedData = $privateKeyCryptographer->decrypt($encryptedData);
                $this->assertEquals($expected = $data, $actual = $decryptedData);
            } finally {
                $certificate->close();
            }
        } finally {
            $privateKey->close();
        }
    }

}
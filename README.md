[![Build Status](https://travis-ci.org/tagadvance/Elephant-Encryption.svg?branch=master)](https://travis-ci.org/tagadvance/Elephant-Encryption)

# Elephant Encryption

Elephant Encryption was originally a part of [Gilligan](https://github.com/tagadvance/Gilligan). Please bear in mind that while the encryption itself is very strong, data is only as secure as the server storing the private key.

## Goal
The goal was and is to create a well-structured, strongly-typed library to wrap around PHP's poorly documented OpenSSL extension.

## Download / Install
The easiest way to install Elephant Encryption is via Composer:
```bash
composer require "tagadvance/elephant:dev-master"
```
```json
{
    "require": {
        "tagadvance/elephant": "dev-master"
    }
}
```

## Example
```php
<?php

use tagadvance\elephant\cryptography\CertificateSigningRequest;
use tagadvance\elephant\cryptography\ConfigurationBuilder;
use tagadvance\elephant\cryptography\distinguishedname\DistinguishedNameBuilder;
use tagadvance\elephant\cryptography\PrivateKey;
use tagadvance\gilligan\io\File;
use tagadvance\gilligan\security\Hash;

require_once 'vendor/autoload.php';

define('KEY_PATH', '/tmp/elephant.key');
define('CSR_PATH', '/tmp/elephant.csr');
define('CERTIFICATE_PATH', '/tmp/elephant.cert');
define('ELEPHANT_PASSWORD', null);

$configuration = ConfigurationBuilder::builder()
    ->setConfigurationFile(ConfigurationBuilder::CONFIG_DEBIAN)
    ->setDigestAlgorithm(Hash::ALGORITHM_SHA512)
    ->setX509Extensions('v3_ca')
    ->setRequiredExtensions('v3_req')
    ->setPrivateKeyBits(4096)
    ->setPrivateKeyType();
$privateKey = PrivateKey::newPrivateKey($configuration);
$file = new File(KEY_PATH);
$privateKey->exportToFile($file, ELEPHANT_PASSWORD, $configuration->build());

$dn = DistinguishedNameBuilder::builder()
    ->setCountryName('US')
    ->setStateOrProvinceName('OR')
    ->setLocality('Crater Lake')
    ->setOrganizationName('Acme Corporation')
    ->setOrganizationUnitName('.')
    ->setCommonName('Wile E Coyote')
    ->setEmailAddress('w.coyote@acme.com');
$csr = CertificateSigningRequest::newCertificateSigningRequest($dn, $privateKey);
$file = new File(CSR_PATH);
$csr->exportToFile($file, $human = false);

$certificate = $csr->sign($privateKey);
$file = new File(CERTIFICATE_PATH);
$certificate->exportToFile($file);
```

```bash
$data = <<<DATA
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad
minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit
in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia
deserunt mollit anim id est laborum.
DATA;

$privateKey = PrivateKey::createFromFile(new File(KEY_PATH), ELEPHANT_PASSWORD);
$certificate = Certificate::createFromFile(new File(CERTIFICATE_PATH));
$publicKey = PublicKey::createFromCertificate($certificate);

$publicKeyCryptographer = Base64Cryptographer::create(new PublicKeyCryptographer($privateKey, $publicKey));
$encryptedData = $publicKeyCryptographer->encrypt($data);
Standard::output()->printLine("Encrypted Data: $encryptedData");

$privateKeyCryptographer = Base64Cryptographer::create(new PrivateKeyCryptographer($privateKey));
$decryptedData = $privateKeyCryptographer->decrypt($encryptedData);
Standard::output()->printLine("Decrypted Data: $decryptedData");
```

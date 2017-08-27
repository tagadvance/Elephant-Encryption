<?php

namespace tagadvance\elephant\cryptography;

use tagadvance\gilligan\io\File;
use tagadvance\gilligan\io\FileOutputStream;
use tagadvance\gilligan\io\IOException;

class PublicKey {

    /**
     *
     * @var string
     */
    private $key;

    static function createFromCertificate(Certificate $certificate) {
        $key = '';
        $isExported = openssl_x509_export($certificate->getCertificate(), $key);
        if (! $isExported) {
            throw new CryptographyException();
        }
        return new self($key);
    }

    function __construct(string $key) {
        $this->key = $key;
    }

    function getKey(): string {
        return $this->key;
    }

    function getDetails(): array {
        $details = openssl_pkey_get_details($this->key);
        if ($details === false) {
            throw new CryptographyException();
        }
        return $details;
    }

    function calculateEncryptSize() {
        return $this->calculateDecryptSize() - OpenSSL::PADDING;
    }

    function calculateDecryptSize() {
        $details = $this->getDetails();
        $bits = $details['bits'];
        return $bits / $bitsPerByte = 8;
    }

}
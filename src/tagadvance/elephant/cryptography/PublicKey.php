<?php

namespace tagadvance\elephant\cryptography;

class PublicKey {

    /**
     *
     * @var string
     */
    private $key;

    static function createFromCertificate(Certificate $certificate) {
        $key = '';
        $isExported = openssl_x509_export($certificate->getCertificate(), $key);
        if ($isExported) {
            return new self($key);
        }
        throw new CryptographyException('could not create public key from certificate');
    }

    /**
     *
     * @param string $key
     */
    function __construct(string $key) {
        $this->key = $key;
    }

    /**
     *
     * @return string
     */
    function getKey(): string {
        return $this->key;
    }

    /**
     *
     * @return int
     */
    function calculateEncryptSize(): int {
        return $this->calculateDecryptSize() - OpenSSL::PADDING;
    }

    /**
     *
     * @return int
     */
    function calculateDecryptSize(): int {
        $details = $this->getDetails();
        $bits = $details['bits'];
        return $bits / $bitsPerByte = 8;
    }

}
<?php

namespace tagadvance\elephant\cryptography;

class PublicKey
{
    /**
     *
     * @var string
     */
    private string $key;

    /**
     *
     * @param Certificate $certificate
     * @throws CryptographyException
     * @return self
     */
    public static function createFromCertificate(Certificate $certificate): self
    {
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
    public function __construct(string $key)
    {
        $this->key = $key;
    }

    /**
     *
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     *
     * @return int
     */
    public function calculateEncryptSize(): int
    {
        return $this->calculateDecryptSize() - OpenSSL::PADDING;
    }

    /**
     *
     * @throws CryptographyException
     * @return array
     * @see http://php.net/manual/en/function.openssl-pkey-get-details.php
     */
    public function getDetails(): array
    {
        $key = openssl_pkey_get_public($this->key);
        if ($key === false) {
            throw new CryptographyException('could not read public key');
        }
        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new CryptographyException('could not get details');
        }
        return $details;
    }

    /**
     *
     * @return int
     */
    public function calculateDecryptSize(): int
    {
        $details = $this->getDetails();
        $bits = $details['bits'];
        return $bits / $bitsPerByte = 8;
    }

}

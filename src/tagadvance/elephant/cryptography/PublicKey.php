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
     * @return int
     */
    public function calculateDecryptSize(): int
    {
        $details = $this->getDetails();
        $bits = $details['bits'];
        return $bits / $bitsPerByte = 8;
    }

}

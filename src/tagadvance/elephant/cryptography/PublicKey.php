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
        OpenSSL::call(
            function () use ($certificate, &$key) {
                return openssl_x509_export($certificate->getCertificate(), $key);
            },
            'could not create public key from certificate',
        );

        return new self($key);
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
     * Public-key encryption uses OAEP, so the overhead is OAEP's and not PKCS #1 v1.5's.
     * PrivateKey::calculateEncryptSize() subtracts the smaller PADDING because
     * private-key encryption is a v1.5 signature operation.
     *
     * @return int
     */
    public function calculateEncryptSize(): int
    {
        return $this->calculateDecryptSize() - OpenSSL::OAEP_PADDING;
    }

    /**
     *
     * @throws CryptographyException
     * @return array
     * @see http://php.net/manual/en/function.openssl-pkey-get-details.php
     */
    public function getDetails(): array
    {
        $key = OpenSSL::call(
            fn() => openssl_pkey_get_public($this->key),
            'could not read public key',
        );

        return OpenSSL::call(
            fn() => openssl_pkey_get_details($key),
            'could not get details',
        );
    }

    /**
     *
     * @return int
     */
    public function calculateDecryptSize(): int
    {
        $details = $this->getDetails();
        $bits = $details['bits'];
        $bitsPerByte = 8;
        return intdiv($bits + $bitsPerByte - 1, $bitsPerByte);
    }

}

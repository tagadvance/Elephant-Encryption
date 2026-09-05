<?php

namespace tagadvance\elephant\cryptography;

use OpenSSLAsymmetricKey;

class PublicKey
{
    private OpenSSLAsymmetricKey $key;

    /**
     * Takes the public key out of a certificate. openssl will accept a certificate wherever
     * a public key is wanted, but the two are not interchangeable to a reader, so the key is
     * extracted here rather than carried around as a certificate.
     *
     * @throws CryptographyException if the certificate carries no readable public key
     */
    public static function createFromCertificate(Certificate $certificate): self
    {
        $key = OpenSSL::call(
            fn() => openssl_pkey_get_public($certificate->getCertificate()),
            'could not create public key from certificate',
        );

        return new self($key);
    }

    /**
     * @param string $pem a PEM-encoded public key, or a certificate to take one from
     * @throws CryptographyException if the PEM cannot be read as a public key
     */
    public static function createFromPem(string $pem): self
    {
        $key = OpenSSL::call(
            fn() => openssl_pkey_get_public($pem),
            'could not read public key',
        );

        return new self($key);
    }

    private function __construct(OpenSSLAsymmetricKey $key)
    {
        $this->key = $key;
    }

    public function getKey(): OpenSSLAsymmetricKey
    {
        return $this->key;
    }

    /**
     * The largest plaintext a single encrypt can take.
     *
     * Public-key encryption uses OAEP, so the overhead is OAEP's and not PKCS #1 v1.5's.
     * PrivateKey::calculateEncryptSize() subtracts the smaller PADDING because private-key
     * encryption is a v1.5 signature operation.
     */
    public function calculateEncryptSize(): int
    {
        return $this->calculateDecryptSize() - OpenSSL::OAEP_PADDING;
    }

    /**
     * @return array the key's details, as documented for openssl_pkey_get_details()
     * @throws CryptographyException if the details cannot be read
     * @see https://www.php.net/manual/en/function.openssl-pkey-get-details.php
     */
    public function getDetails(): array
    {
        return OpenSSL::call(
            fn() => openssl_pkey_get_details($this->key),
            'could not get details',
        );
    }

    /**
     * The size of one ciphertext block, which is the modulus rounded up to whole bytes.
     */
    public function calculateDecryptSize(): int
    {
        $details = $this->getDetails();
        $bits = $details['bits'];
        $bitsPerByte = 8;
        return intdiv($bits + $bitsPerByte - 1, $bitsPerByte);
    }

}

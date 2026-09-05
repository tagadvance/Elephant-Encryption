<?php

namespace tagadvance\elephant\cryptography;

use OpenSSLAsymmetricKey;
use SplFileInfo;

/**
 * An RSA private key. The matching public key is reachable via getDetails()['key'].
 */
class PrivateKey
{
    private OpenSSLAsymmetricKey $key;

    /**
     * Generates a new key.
     *
     * @throws CryptographyException if the configuration is rejected, e.g. too few key bits
     * @see https://www.php.net/manual/en/function.openssl-pkey-new.php
     */
    public static function newPrivateKey(ConfigurationBuilder $builder): self
    {
        $configArgs = $builder->build();
        $key = OpenSSL::call(
            fn() => openssl_pkey_new($configArgs),
            'could not create private key',
        );

        return new self($key);
    }

    /**
     * @param string|null $password required only if the key on disk is encrypted
     * @throws CryptographyException if the key cannot be read or the password is wrong
     * @see https://www.php.net/manual/en/function.openssl-pkey-get-private.php
     */
    public static function createFromFile(SplFileInfo $file, ?string $password = null): self
    {
        $path = $file->getRealPath();
        $filePath = "file://$path";
        $key = OpenSSL::call(
            fn() => openssl_pkey_get_private($filePath, $password),
            'key could not be read',
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
     * @return array the key's details; ['key'] is the matching public key in PEM form
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
     * The largest plaintext a single private-key encrypt can take.
     *
     * Private-key encryption is a PKCS #1 v1.5 signature operation, so the overhead is the
     * smaller PADDING. PublicKey::calculateEncryptSize() subtracts OAEP_PADDING instead.
     */
    public function calculateEncryptSize(): int
    {
        return $this->calculateDecryptSize() - OpenSSL::PADDING;
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

    /**
     * @param string|null $password encrypts the exported key; omit for an unencrypted PEM
     * @param array|null $configuration openssl config, as built by ConfigurationBuilder
     * @throws CryptographyException if the key cannot be exported
     */
    public function export(?string $password = null, ?array $configuration = null): string
    {
        $output = '';
        OpenSSL::call(
            function () use (&$output, $password, $configuration) {
                return openssl_pkey_export($this->key, $output, $password, $configuration);
            },
            'private key could not be exported',
        );

        return $output;
    }

    /**
     * @param string|null $password encrypts the exported key; omit for an unencrypted PEM
     * @param array|null $configuration openssl config, as built by ConfigurationBuilder
     * @throws CryptographyException if the file cannot be written
     * @see https://www.php.net/manual/en/function.openssl-pkey-export-to-file.php
     */
    public function exportToFile(SplFileInfo $file, ?string $password = null, ?array $configuration = null): void
    {
        $path = $file->getPathname();
        OpenSSL::call(
            fn() => openssl_pkey_export_to_file($this->key, $path, $password, $configuration),
            'private key could not be saved',
        );
    }

}

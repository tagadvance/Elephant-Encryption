<?php

namespace tagadvance\elephant\cryptography;

use OpenSSLAsymmetricKey;
use SplFileInfo;

class PrivateKey
{
    private OpenSSLAsymmetricKey $key;

    /**
     *
     * @param ConfigurationBuilder $builder
     * @throws CryptographyException
     * @return self
     * @see http://php.net/manual/en/function.openssl-pkey-new.php
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
     *
     * @param SplFileInfo $file
     * @param string|null $password
     * @return self
     * @see http://php.net/manual/en/function.openssl-pkey-get-private.php
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

    /**
     *
     * @param OpenSSLAsymmetricKey $key
     */
    private function __construct(OpenSSLAsymmetricKey $key)
    {
        $this->key = $key;
    }

    public function getKey(): OpenSSLAsymmetricKey
    {
        return $this->key;
    }

    /**
     *
     * @throws CryptographyException
     * @return array
     * @see http://php.net/manual/en/function.openssl-pkey-get-details.php
     */
    public function getDetails(): array
    {
        return OpenSSL::call(
            fn() => openssl_pkey_get_details($this->key),
            'could not get details',
        );
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
        $bitsPerByte = 8;
        return intdiv($bits + $bitsPerByte - 1, $bitsPerByte);
    }

    /**
     *
     * @param string|null $password
     * @param array|null $configuration
     * @return string
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
     *
     * @param SplFileInfo $file
     * @param string|null $password
     * @param array|null $configuration
     * @see http://php.net/manual/en/function.openssl-pkey-export-to-file.php
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

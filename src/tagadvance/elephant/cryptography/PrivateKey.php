<?php

namespace tagadvance\elephant\cryptography;

use OpenSSLAsymmetricKey;
use SplFileInfo;
use Throwable;

class PrivateKey {

    /**
     *
     * @var resource
     */
    private $key;

    /**
     *
     * @param ConfigurationBuilder $builder
     * @throws CryptographyException
     * @return self
     * @see http://php.net/manual/en/function.openssl-pkey-new.php
     */
    static function newPrivateKey(ConfigurationBuilder $builder): self {
        $configArgs = $builder->build();
        try {
            $key = openssl_pkey_new($configArgs);
            if ($key !== false) {
                return new self($key);
            }
        } catch (Throwable $t) {
            throw new CryptographyException('could not create private key', $code = null, $t);
        }

        throw new CryptographyException('could not create private key');
    }

    /**
     *
     * @param SplFileInfo $file
     * @param string|null $password
     * @return self
     * @see http://php.net/manual/en/function.openssl-pkey-get-private.php
     */
    static function createFromFile(SplFileInfo $file, string $password = null): self {
        $path = $file->getRealPath();
        $filePath = "file://$path";
        $key = openssl_pkey_get_private($filePath, $password);
        if ($key !== false) {
            return new self($key);
        }
        throw new CryptographyException('key could not be read');
    }

    /**
     * 
     * @param OpenSSLAsymmetricKey $key
     */
    private function __construct(OpenSSLAsymmetricKey $key) {
        $this->key = $key;
    }

    /**
     * 
     * @return resource
     */
    function getKey() {
        return $this->key;
    }

    /**
     *
     * @throws CryptographyException
     * @return array
     * @see http://php.net/manual/en/function.openssl-pkey-get-details.php
     */
    function getDetails(): array {
        $details = openssl_pkey_get_details($this->key);
        if ($details === false) {
            throw new CryptographyException('could not get details');
        }
        return $details;
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

    /**
     *
     * @param string|null $password
     * @param array|null $configuration
     * @return string
     */
    function export(string $password = null, array $configuration = null): string {
        $output = '';
        $isExported = openssl_pkey_export($this->key, $output, $password, $configuration);
        if ($isExported) {
            return $output;
        }
        throw new CryptographyException('private key could not be exported');
    }

    /**
     *
     * @param SplFileInfo $file
     * @param string|null $password
     * @param array|null $configuration
     * @see http://php.net/manual/en/function.openssl-pkey-export-to-file.php
     */
    function exportToFile(SplFileInfo $file, string $password = null, array $configuration = null): void {
        $path = $file->getPathname();
        $result = openssl_pkey_export_to_file($this->key, $path, $password, $configuration);
        if (! $result) {
            throw new CryptographyException('private key could not be saved');
        }
    }

}

<?php

namespace tagadvance\elephant\cryptography;

use tagadvance\gilligan\io\Closeable;

class PrivateKey implements Closeable {

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
        $key = openssl_pkey_new($configArgs);
        if ($key === false) {
            throw new CryptographyException('could not create private key');
        }
        return new self($key);
    }

    /**
     *
     * @param \SplFileInfo $file
     * @param string $password
     * @throws CryptographyException
     * @return self
     * @see http://php.net/manual/en/function.openssl-pkey-get-private.php
     */
    static function createFromFile(\SplFileInfo $file, string $password = null): self {
        $path = $file->getRealPath();
        $filePath = "file://$path";
        $key = openssl_pkey_get_private($filePath, $password);
        if ($key === false) {
            throw new CryptographyException('key could not be read');
        }
        return new self($key);
    }

    private function __construct($key) {
        if (! is_resource($key)) {
            $message = '$key must be a resource';
            throw new \InvalidArgumentException($message);
        }
        
        $this->key = $key;
    }

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
            throw new CryptographyException();
        }
        return $details;
    }

    function calculateEncryptSize(): int {
        return $this->calculateDecryptSize() - OpenSSL::PADDING;
    }

    function calculateDecryptSize(): int {
        $details = $this->getDetails();
        $bits = $details['bits'];
        return $bits / $bitsPerByte = 8;
    }

    function close(): void {
        openssl_pkey_free($this->key);
        unset($this->key);
    }

    /**
     *
     * @param string $password
     * @param array $config
     * @throws CryptographyException
     * @return string
     */
    function export(string $password = null, array $config = null): string {
        $output = '';
        $isExported = openssl_pkey_export($this->key, $output, $password, $config);
        if (! $isExported) {
            throw new CryptographyException('private key could not be exported');
        }
        return $output;
    }

    /**
     *
     * @param \SplFileInfo $file
     * @param string $password
     * @param array $config
     * @throws CryptographyException
     * @see http://php.net/manual/en/function.openssl-pkey-export-to-file.php
     */
    function exportToFile(\SplFileInfo $file, string $password = null, array $config = null): void {
        $path = $file->getPathname();
        $result = openssl_pkey_export_to_file($this->key, $path, $password, $config);
        if (! $result) {
            throw new CryptographyException('private key could not be saved');
        }
    }

}
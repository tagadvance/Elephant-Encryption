<?php

namespace tagadvance\elephant\cryptography;

use tagadvance\gilligan\io\Closeable;

class PrivateKey implements Closeable {

    /**
     *
     * @var resource
     */
    private $key;

    static function newPrivateKey(ConfigurationBuilder $builder) {
        $configArgs = $builder->build();
        $key = openssl_pkey_new($configArgs);
        if ($key === false) {
            throw new CryptographyException();
        }
        return new self($key);
    }
    
    static function createFromFile(\SplFileInfo $file, string $password = null) {
        $path = $file->getRealPath();
        $filePath = "file://$path";
        $key = openssl_pkey_get_private($filePath, $password);
        if ($key === false) {
            throw new CryptographyException('key could not be read');
        }
        return new self($key);
    }

    function __construct($key) {
        if (! is_resource($key)) {
            $message = '$key must be a resource';
            throw new \InvalidArgumentException($message);
        }
        
        $this->key = $key;
    }

    function getKey() {
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

    function close() {
        openssl_pkey_free($this->key);
        unset($this->key);
    }

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
    function exportToFile(\SplFileInfo $file, string $password = null, array $config = null) {
        $path = $file->getPathname();
        $result = openssl_pkey_export_to_file($this->key, $path, $password, $config);
        if (! $result) {
            throw new CryptographyException('private key could not be saved');
        }
    }

}
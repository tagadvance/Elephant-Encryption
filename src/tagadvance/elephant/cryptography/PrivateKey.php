<?php

namespace tagadvance\elephant\cryptography;

use tagadvance\gilligan\io\Closeable;
use tagadvance\gilligan\io\File;

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

    static function createFromFile(File $file, string $password = null) {
        $path = $file->getRealPath();
        $filePath = "file://$path";
        $key = openssl_pkey_get_private($filePath, $password);
        if ($key === false) {
            throw new CryptographyException();
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

}
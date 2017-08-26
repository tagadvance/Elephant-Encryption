<?php

namespace tagadvance\elephant\cryptography;

class PublicKeyCryptographer extends AbstractCryptographer {

    /**
     *
     * @var PrivateKey
     */
    private $privateKey;

    /**
     *
     * @var PublicKey
     */
    private $publicKey;

    function __construct(PrivateKey $privateKey, PublicKey $publicKey) {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    function getKey(): string {
        return $this->publicKey;
    }

    function encrypt(string $data): string {
        $key = $this->publicKey->getKey();
        $function = function ($input, &$output) use (&$key) {
            return openssl_public_encrypt($input, $output, $key, OPENSSL_PKCS1_OAEP_PADDING);
        };
        $size = $this->privateKey->calculateEncryptSize();
        return $this->doCrypt($function, $data, $size);
    }

    function decrypt(string $data): string {
        $key = $this->publicKey->getKey();
        $function = function ($input, &$output) use (&$key) {
            return openssl_public_decrypt($input, $output, $key, OPENSSL_PKCS1_PADDING);
        };
        $size = $this->privateKey->calculateDecryptSize();
        return $this->doCrypt($function, $data, $size);
    }

}
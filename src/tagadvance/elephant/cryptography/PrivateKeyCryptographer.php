<?php

namespace tagadvance\elephant\cryptography;

class PrivateKeyCryptographer extends AbstractCryptographer {

    /**
     *
     * @var PrivateKey
     */
    private PrivateKey $key;

    /**
     * 
     * @param PrivateKey $key
     */
    function __construct(PrivateKey $key) {
        $this->key = $key;
    }

    /**
     * 
     * {@inheritDoc}
     * @see Cryptographer::encrypt
     */
    function encrypt(string $data): string {
        $key = $this->key->getKey();
        $function = function ($input, &$output) use (&$key) {
            return openssl_private_encrypt($input, $output, $key);
        };
        $size = $this->key->calculateEncryptSize();
        return $this->doCrypt($function, $data, $size);
    }

    /**
     * 
     * {@inheritDoc}
     * @see Cryptographer::decrypt
     */
    function decrypt(string $data): string {
        $key = $this->key->getKey();
        $function = function ($input, &$output) use (&$key) {
            return openssl_private_decrypt($input, $output, $key, OPENSSL_PKCS1_OAEP_PADDING);
        };
        $size = $this->key->calculateDecryptSize();
        return $this->doCrypt($function, $data, $size);
    }

}

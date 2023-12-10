<?php

namespace tagadvance\elephant\cryptography;

class PublicKeyCryptographer extends AbstractCryptographer {

    /**
     *
     * @var PrivateKey
     */
    private PrivateKey $privateKey;

    /**
     *
     * @var PublicKey
     */
    private PublicKey $publicKey;

    /**
     *
     * @param PrivateKey $privateKey
     * @param PublicKey $publicKey
     */
    function __construct(PrivateKey $privateKey, PublicKey $publicKey) {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    /**
     *
     * @return PublicKey
     */
    function getKey(): PublicKey {
        return $this->publicKey;
    }

    /**
     *
     * {@inheritdoc}
     * @see Cryptographer::encrypt
     */
    function encrypt(string $data): string {
        $key = $this->publicKey->getKey();
        $function = function ($input, &$output) use (&$key) {
            return openssl_public_encrypt($input, $output, $key, OPENSSL_PKCS1_OAEP_PADDING);
        };
        $size = $this->privateKey->calculateEncryptSize();
        return $this->doCrypt($function, $data, $size);
    }

    /**
     *
     * {@inheritdoc}
     * @see Cryptographer::decrypt
     */
    function decrypt(string $data): string {
        $key = $this->publicKey->getKey();
        $function = function ($input, &$output) use (&$key) {
            return openssl_public_decrypt($input, $output, $key);
        };
        $size = $this->privateKey->calculateDecryptSize();
        return $this->doCrypt($function, $data, $size);
    }

}

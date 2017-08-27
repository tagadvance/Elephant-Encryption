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
     * @return string
     */
    function getKey(): string {
        return $this->publicKey;
    }

    /**
     *
     * {@inheritdoc}
     * @see \tagadvance\elephant\cryptography\Cryptographer::encrypt()
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
     * @see \tagadvance\elephant\cryptography\Cryptographer::decrypt()
     */
    function decrypt(string $data): string {
        $key = $this->publicKey->getKey();
        $function = function ($input, &$output) use (&$key) {
            return openssl_public_decrypt($input, $output, $key, OPENSSL_PKCS1_PADDING);
        };
        $size = $this->privateKey->calculateDecryptSize();
        return $this->doCrypt($function, $data, $size);
    }

}
<?php

namespace tagadvance\elephant\cryptography;

/**
 * Encrypts with a public key using OAEP, and verifies with it using PKCS #1 v1.5.
 *
 * encrypt() gives real confidentiality and is undone by PrivateKeyCryptographer::decrypt().
 * decrypt() is the verify half of a signature and undoes
 * PrivateKeyCryptographer::encrypt() — the two methods here are not each other's inverse.
 */
class PublicKeyCryptographer extends AbstractCryptographer
{
    private PublicKey $publicKey;

    public function __construct(PublicKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    public function getKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     * @see Cryptographer::encrypt
     */
    public function encrypt(string $data): string
    {
        $key = $this->publicKey->getKey();
        $function = function ($input, &$output) use (&$key) {
            return openssl_public_encrypt($input, $output, $key, OPENSSL_PKCS1_OAEP_PADDING);
        };
        $size = $this->publicKey->calculateEncryptSize();
        return $this->doCrypt($function, $data, $size, 'could not encrypt data with the public key');
    }

    /**
     * Recovers data written by PrivateKeyCryptographer::encrypt(). This is signature
     * verification, not decryption — it proves the private key produced the input.
     *
     * {@inheritdoc}
     * @see Cryptographer::decrypt
     */
    public function decrypt(string $data): string
    {
        $key = $this->publicKey->getKey();
        $function = function ($input, &$output) use (&$key) {
            return openssl_public_decrypt($input, $output, $key);
        };
        $size = $this->publicKey->calculateDecryptSize();
        return $this->doCrypt($function, $data, $size, 'could not decrypt data with the public key');
    }

}

<?php

namespace tagadvance\elephant\cryptography;

/**
 * Signs with a private key using PKCS #1 v1.5, and decrypts with it using OAEP.
 *
 * decrypt() undoes PublicKeyCryptographer::encrypt(). The two methods here are not each
 * other's inverse.
 */
class PrivateKeyCryptographer extends AbstractCryptographer
{
    private PrivateKey $key;

    public function __construct(PrivateKey $key)
    {
        $this->key = $key;
    }

    /**
     * Signs rather than conceals: the result is recoverable by anyone holding the public key,
     * so it provides authenticity, never confidentiality. Undone by
     * PublicKeyCryptographer::decrypt().
     *
     * {@inheritDoc}
     * @see Cryptographer::encrypt
     */
    public function encrypt(string $data): string
    {
        $key = $this->key->getKey();
        $function = function ($input, &$output) use (&$key) {
            return openssl_private_encrypt($input, $output, $key);
        };
        $size = $this->key->calculateEncryptSize();
        return $this->doCrypt($function, $data, $size, 'could not encrypt data with the private key');
    }

    /**
     * {@inheritDoc}
     * @see Cryptographer::decrypt
     */
    public function decrypt(string $data): string
    {
        $key = $this->key->getKey();
        $function = function ($input, &$output) use (&$key) {
            return openssl_private_decrypt($input, $output, $key, OPENSSL_PKCS1_OAEP_PADDING);
        };
        $size = $this->key->calculateDecryptSize();
        return $this->doCrypt($function, $data, $size, 'could not decrypt data with the private key');
    }

}

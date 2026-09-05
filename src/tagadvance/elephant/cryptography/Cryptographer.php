<?php

namespace tagadvance\elephant\cryptography;

/**
 * Encrypts and decrypts data of any length by splitting it into key-sized blocks.
 *
 * The implementations are not their own inverse: a PublicKeyCryptographer encrypt is undone
 * by a PrivateKeyCryptographer decrypt, and a PrivateKeyCryptographer encrypt by a
 * PublicKeyCryptographer decrypt. The two directions use different padding and are not
 * interchangeable.
 */
interface Cryptographer
{
    /**
     * @return string raw ciphertext bytes; wrap in a Base64Cryptographer for text-safe output
     * @throws CryptographyException if any block fails to encrypt
     */
    public function encrypt(string $data): string;

    /**
     * @throws CryptographyException if any block fails to decrypt
     */
    public function decrypt(string $data): string;

}

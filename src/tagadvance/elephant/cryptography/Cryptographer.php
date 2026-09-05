<?php

namespace tagadvance\elephant\cryptography;

interface Cryptographer
{
    /**
     *
     * @param string $data
     * @return string The encrypted data.
     * @throws CryptographyException
     */
    public function encrypt(string $data): string;

    /**
     *
     * @param string $data
     * @return string The decrypted data.
     * @throws CryptographyException
     */
    public function decrypt(string $data): string;

}

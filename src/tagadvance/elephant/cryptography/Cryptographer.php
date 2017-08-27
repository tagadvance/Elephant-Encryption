<?php

namespace tagadvance\elephant\cryptography;

interface Cryptographer {

    /**
     *
     * @param string $data
     * @return string The encrypted data.
     * @throws CryptographyException
     */
    function encrypt(string $data): string;

    /**
     *
     * @param string $data
     * @return string The decrypted data.
     * @throws CryptographyException
     */
    function decrypt(string $data): string;

}
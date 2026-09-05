<?php

namespace tagadvance\elephant\cryptography;

abstract class AbstractCryptographer implements Cryptographer
{
    /**
     * Runs $function over $data one $size block at a time and concatenates the results.
     *
     * Blocks carry no ordering or completeness information, so an attacker can reorder or
     * drop ciphertext blocks and the decrypt still succeeds, yielding reordered or truncated
     * plaintext. Anything needing integrity must add it around this.
     *
     * @param callable $function called as ($input, &$output); returns false on failure
     * @param int $size block size in bytes
     * @param string $message exception message used when a block fails
     * @throws CryptographyException as soon as a block fails
     */
    protected function doCrypt(callable $function, string $data, int $size, string $message): string
    {
        $return = '';
        while ($data !== '') {
            $input = substr($data, $start = 0, $size);

            $output = null;
            OpenSSL::call(function () use ($function, $input, &$output) {
                return $function($input, $output);
            }, $message);
            $return .= $output;

            $data = substr($data, $size);
        }
        return $return;
    }

}

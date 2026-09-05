<?php

namespace tagadvance\elephant\cryptography;

abstract class AbstractCryptographer implements Cryptographer
{
    /**
     *
     * @param callable $function
     * @param string $data
     * @param int $size
     * @param string $message
     * @throws CryptographyException
     * @return string
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

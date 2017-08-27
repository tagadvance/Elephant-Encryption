<?php

namespace tagadvance\elephant\cryptography;

abstract class AbstractCryptographer implements Cryptographer {

    /**
     * 
     * @param callable $function
     * @param string $data
     * @param int $size
     * @throws CryptographyException
     * @return string
     */
    protected function doCrypt(callable $function, string $data, int $size) {
        $return = '';
        while ($data) {
            $input = substr($data, $start = 0, $size);
            
            $output = null;
            $success = $function($input, $output);
            if (! $success) {
                throw new CryptographyException();
            }
            $return .= $output;
            
            $data = substr($data, $size);
        }
        return $return;
    }

}
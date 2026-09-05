<?php

namespace tagadvance\elephant\cryptography;

use tagadvance\gilligan\io\PrintStream;

/**
 *
 * @author Tag <tagadvance+elephant@gmail.com>
 */
class OpenSSL
{
    /**
     *
     * @var integer bytes - 88 bits
     */
    public const PADDING = 11;

    /**
     * Overhead of OAEP padding with the default SHA-1 hash: 2 * 20 + 2.
     *
     * @var integer bytes - 336 bits
     */
    public const OAEP_PADDING = 42;

    private function __construct() {}

    /**
     * Removes all errors in the OpenSSL internal error cache.
     *
     * @return void
     */
    public static function clearErrors(): void
    {
        while (openssl_error_string());
    }

    /**
     * Prints all errors in the OpenSSL internal error cache.
     *
     * @param PrintStream $out
     * @return void
     */
    public static function printErrors(PrintStream $out): void
    {
        for ($i = 0; ($e = openssl_error_string()) !== false; $i++) {
            if ($i == 0) {
                $out->printLine('Errors:');
            }
            $out->printLine("\t$e");
        }
    }

}

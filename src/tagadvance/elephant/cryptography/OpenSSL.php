<?PHP

namespace tagadvance\elephant\cryptography;

use tagadvance\gilligan\base\Extensions;
use tagadvance\gilligan\io\PrintStream;

Extensions::getInstance()->requires('openssl');

/**
 *
 * @author Tag <tagadvance+elephant@gmail.com>
 */
class OpenSSL {

    // bytes - 88 bits
    const PADDING = 11;

    private function __construct() {}

    /**
     * Removes all errors in the OpenSSL internal error cache.
     *
     * @return void
     */
    static function clearErrors() {
        while (openssl_error_string());
    }

    /**
     * Prints all errors in the OpenSSL internal error cache.
     *
     * @return void
     */
    static function printErrors(PrintStream $out) {
        for ($i = 0; ($e = openssl_error_string()) !== false; $i ++) {
            if ($i == 0) {
                $out->printLine('Errors:');
            }
            $out->printLine("\t$e");
        }
    }

}
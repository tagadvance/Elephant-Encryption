<?PHP

namespace tagadvance\elephant\cryptography;

use tagadvance\gilligan\io\PrintStream;

/**
 *
 * @author Tag <tagadvance+elephant@gmail.com>
 */
class OpenSSL {

    /**
     * 
     * @var integer bytes - 88 bits
     */
    const PADDING = 11;

    private function __construct() {}

    /**
     * Removes all errors in the OpenSSL internal error cache.
     *
     * @return void
     */
    static function clearErrors(): void {
        while (openssl_error_string());
    }

    /**
     * Prints all errors in the OpenSSL internal error cache.
     *
     * @param PrintStream $out
     * @return void
     */
    static function printErrors(PrintStream $out): void {
        for ($i = 0; ($e = openssl_error_string()) !== false; $i ++) {
            if ($i == 0) {
                $out->printLine('Errors:');
            }
            $out->printLine("\t$e");
        }
    }

}

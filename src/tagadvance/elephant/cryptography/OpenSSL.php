<?php

namespace tagadvance\elephant\cryptography;

use Throwable;

/**
 * Padding sizes and the wrapper every openssl_* call in this library goes through.
 *
 * @author Tag <tagadvance+elephant@gmail.com>
 */
class OpenSSL
{
    /**
     * Overhead of PKCS #1 v1.5 padding, used by the private-key signature path.
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
     * Invokes an openssl_* function, converting failure into a CryptographyException.
     *
     * The openssl error queue is process-wide and shared with every other consumer in the
     * process, so it is cleared immediately before the call and drained immediately after.
     * That keeps the errors attributable to this call, and keeps the queue from escaping
     * as public API.
     *
     * Warnings raised by the call are captured rather than passed to the application's
     * error handler. They are not redundant: openssl_pkey_new() reports a bad key length
     * only as a PHP warning and leaves the error queue empty, so the warning is the only
     * diagnostic that exists for that failure.
     *
     * @param callable $function takes no arguments; capture any out-parameter by reference
     * @param string $message prefixed to the openssl detail in the exception message
     * @throws CryptographyException if $function returns false or throws
     * @return mixed whatever $function returned, which is never false
     */
    public static function call(callable $function, string $message): mixed
    {
        self::clearErrors();

        $diagnostic = null;
        set_error_handler(function (int $errno, string $error) use (&$diagnostic): bool {
            $diagnostic ??= $error;
            return true;
        }, E_WARNING | E_NOTICE);

        try {
            $result = $function();
        } catch (Throwable $t) {
            throw new CryptographyException($message, $code = 0, $t);
        } finally {
            restore_error_handler();
        }

        if ($result === false) {
            throw CryptographyException::fromOpenSSL($message, self::drainErrors(), $diagnostic);
        }

        return $result;
    }

    /**
     * Empties the openssl error queue so that anything drained afterwards belongs to the
     * call we are about to make, not to some earlier consumer's failure.
     */
    private static function clearErrors(): void
    {
        while (openssl_error_string());
    }

    /**
     * Removes and returns all errors in the OpenSSL internal error cache.
     *
     * @return list<string>
     */
    private static function drainErrors(): array
    {
        $errors = [];
        while (($error = openssl_error_string()) !== false) {
            $errors[] = $error;
        }
        return $errors;
    }

}

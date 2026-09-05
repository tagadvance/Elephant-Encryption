<?php

namespace tagadvance\elephant\cryptography;

use RuntimeException;

class CryptographyException extends RuntimeException
{
    /**
     *
     * @var list<string>
     */
    private array $opensslErrors = [];

    /**
     * Builds an exception describing a failed openssl_* call. The detail is taken from the
     * openssl error queue, falling back to the PHP diagnostic when the queue is empty.
     *
     * @param string $message
     * @param list<string> $opensslErrors
     * @param string|null $diagnostic
     * @return self
     */
    public static function fromOpenSSL(string $message, array $opensslErrors, ?string $diagnostic = null): self
    {
        $detail = $opensslErrors !== [] ? implode('; ', $opensslErrors) : $diagnostic;

        $exception = new self($detail !== null ? "$message: $detail" : $message);
        $exception->opensslErrors = $opensslErrors;

        return $exception;
    }

    /**
     * The openssl error queue as it stood when this exception was raised.
     *
     * @return list<string>
     */
    public function getOpenSSLErrors(): array
    {
        return $this->opensslErrors;
    }

}

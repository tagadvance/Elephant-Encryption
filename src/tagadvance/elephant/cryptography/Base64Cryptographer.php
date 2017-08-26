<?php

namespace tagadvance\elephant\cryptography;

class Base64Cryptographer implements Cryptographer {

    /**
     *
     * @var Cryptographer
     */
    private $delegate;

    static function create(Cryptographer $delegate) {
        return new self($delegate);
    }

    function __construct(Cryptographer $delegate) {
        $this->delegate = $delegate;
    }

    function encrypt(string $data): string {
        return base64_encode($this->delegate->encrypt($data));
    }

    function decrypt(string $data): string {
        return $this->delegate->decrypt(base64_decode($data));
    }

}
<?php

namespace tagadvance\elephant\cryptography;

class Base64Cryptographer implements Cryptographer {

    /**
     *
     * @var Cryptographer
     */
    private $delegate;

    /**
     *
     * @param Cryptographer $delegate
     * @return \tagadvance\elephant\cryptography\Base64Cryptographer
     */
    static function create(Cryptographer $delegate) {
        return new self($delegate);
    }

    /**
     *
     * @param Cryptographer $delegate
     */
    function __construct(Cryptographer $delegate) {
        $this->delegate = $delegate;
    }

    /**
     *
     * {@inheritdoc}
     * @see \tagadvance\elephant\cryptography\Cryptographer::encrypt()
     */
    function encrypt(string $data): string {
        return base64_encode($this->delegate->encrypt($data));
    }

    /**
     *
     * {@inheritdoc}
     * @see \tagadvance\elephant\cryptography\Cryptographer::decrypt()
     */
    function decrypt(string $data): string {
        return $this->delegate->decrypt(base64_decode($data));
    }

}
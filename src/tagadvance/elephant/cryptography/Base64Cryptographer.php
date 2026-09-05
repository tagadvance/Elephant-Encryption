<?php

namespace tagadvance\elephant\cryptography;

class Base64Cryptographer implements Cryptographer
{
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
    public static function create(Cryptographer $delegate)
    {
        return new self($delegate);
    }

    /**
     *
     * @param Cryptographer $delegate
     */
    public function __construct(Cryptographer $delegate)
    {
        $this->delegate = $delegate;
    }

    /**
     *
     * {@inheritdoc}
     * @see \tagadvance\elephant\cryptography\Cryptographer::encrypt()
     */
    public function encrypt(string $data): string
    {
        return base64_encode($this->delegate->encrypt($data));
    }

    /**
     *
     * {@inheritdoc}
     * @see \tagadvance\elephant\cryptography\Cryptographer::decrypt()
     */
    public function decrypt(string $data): string
    {
        return $this->delegate->decrypt(base64_decode($data));
    }

}

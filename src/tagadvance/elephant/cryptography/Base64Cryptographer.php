<?php

namespace tagadvance\elephant\cryptography;

/**
 * Wraps another Cryptographer so its raw ciphertext bytes survive being stored or
 * transmitted as text.
 */
class Base64Cryptographer implements Cryptographer
{
    private Cryptographer $delegate;

    public static function create(Cryptographer $delegate): self
    {
        return new self($delegate);
    }

    public function __construct(Cryptographer $delegate)
    {
        $this->delegate = $delegate;
    }

    /**
     * {@inheritdoc}
     * @see \tagadvance\elephant\cryptography\Cryptographer::encrypt()
     */
    public function encrypt(string $data): string
    {
        return base64_encode($this->delegate->encrypt($data));
    }

    /**
     * Decoding is strict, so malformed input is rejected here rather than being salvaged
     * into bytes that fail confusingly further down.
     *
     * @throws CryptographyException if $data is not valid base64
     * {@inheritdoc}
     * @see \tagadvance\elephant\cryptography\Cryptographer::decrypt()
     */
    public function decrypt(string $data): string
    {
        $decoded = base64_decode($data, $strict = true);
        if ($decoded === false) {
            throw new CryptographyException('input is not valid base64');
        }
        return $this->delegate->decrypt($decoded);
    }

}

<?php

namespace tagadvance\elephant\cryptography;

/**
 * OpenSSL Configuration build with fluent interface.
 *
 * @author Tag <tagadvance+elephant@gmail.com>
 * @see http://php.net/manual/en/function.openssl-csr-new.php
 */
class ConfigurationBuilder
{
    /**
     * Debian and derivatives, e.g. Ubuntu, Mint, etc...
     *
     * @var string
     */
    public const CONFIG_DEBIAN = '/etc/ssl/openssl.cnf';

    /**
     * RHEL and derivatives, e.g. CentOS, Redhat, Fedora, etc...
     *
     * @var string
     */
    public const CONFIG_RHEL = '/etc/pki/tls/openssl.cnf';

    /**
     * FIXME: windows
     *
     * @var string|null
     */
    public const CONFIG_WINDOWS = null;

    private const MINIMUM_RECOMMENDED_KEY_SIZE = 2048;

    private array $args;

    public static function builder(): self
    {
        return new self();
    }

    public function __construct()
    {
        $this->args = [];
    }

    /**
     * @param string $filename an openssl.cnf; the CONFIG_* constants cover the common distros
     */
    public function setConfigurationFile(string $filename): self
    {
        $this->args['config'] = $filename;
        return $this;
    }

    /**
     * Select which digest method to use.
     *
     * @param string $algorithm e.g. 'sha512'
     */
    public function setDigestAlgorithm(string $algorithm): self
    {
        $this->args['digest_alg'] = $algorithm;
        return $this;
    }

    /**
     * Select which extensions should be used when creating an x509 certificate.
     *
     * @param string $extensions e.g. 'v3_ca'
     */
    public function setX509Extensions(string $extensions): self
    {
        $this->args['x509_extensions'] = $extensions;
        return $this;
    }

    /**
     * Select which extensions should be used when creating a CSR.
     *
     * @param string $extensions e.g. 'v3_req'
     */
    public function setRequiredExtensions(string $extensions): self
    {
        $this->args['req_extensions'] = $extensions;
        return $this;
    }

    /**
     * Specify how many bits should be used to generate a private key.
     *
     * Warns via E_USER_WARNING below 2048 bits but still accepts the value.
     *
     * @param int $bits e.g. 4096
     */
    public function setPrivateKeyBits(int $bits): self
    {
        if ($bits < self::MINIMUM_RECOMMENDED_KEY_SIZE) {
            $message = sprintf('minimum recommended key size is %d bits', self::MINIMUM_RECOMMENDED_KEY_SIZE);
            trigger_error($message, E_USER_WARNING);
        }

        $this->args['private_key_bits'] = $bits;
        return $this;
    }

    /**
     * Specify the type of private key to create.
     * This can be one of OPENSSL_KEYTYPE_DSA, OPENSSL_KEYTYPE_DH or OPENSSL_KEYTYPE_RSA. The default value is OPENSSL_KEYTYPE_RSA which is currently the only supported key type.
     *
     * @param int $type e.g. OPENSSL_KEYTYPE_RSA
     */
    public function setPrivateKeyType(int $type = OPENSSL_KEYTYPE_RSA): self
    {
        $this->args['private_key_type'] = $type;
        return $this;
    }

    /**
     * Should an exported key (with passphrase) be encrypted?
     */
    public function encryptKey(bool $b = true): self
    {
        $this->args['encrypt_key'] = $b;
        return $this;
    }

    /**
     * @param int $cypher one of the OPENSSL_CIPHER_* constants
     * @see https://www.php.net/manual/en/openssl.ciphers.php
     */
    public function withCypher(int $cypher): self
    {
        $this->args['encrypt_key_cipher'] = $cypher;
        return $this;
    }

    /**
     * @return array the config array openssl_pkey_new() and openssl_csr_new() expect
     */
    public function build(): array
    {
        return $this->args;
    }

}

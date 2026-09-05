<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

/**
 * The finished distinguished name. Construct one directly to bypass the builder chain.
 */
class ArrayBuilder
{
    private array $args;

    public function __construct(array $args)
    {
        $this->args = $args;
    }

    /**
     * @return array the distinguished name openssl_csr_new() expects
     */
    public function build(): array
    {
        return $this->args;
    }

}

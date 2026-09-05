<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

class CommonBuilder
{
    private array $args;

    public function __construct(array $args)
    {
        $this->args = $args;
    }

    /**
     * @param string $name e.g. 'Son, Goku'
     */
    public function setCommonName(string $name): EmailAddressBuilder
    {
        $this->args['commonName'] = $name;
        return new EmailAddressBuilder($this->args);
    }

}

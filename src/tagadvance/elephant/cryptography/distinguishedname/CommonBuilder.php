<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

class CommonBuilder
{

    private array $args;

    function __construct(array $args)
    {
        $this->args = $args;
    }

    /**
     *
     * @param string $name
     *            e.g. 'Son, Goku'
     * @return EmailAddressBuilder
     */
    function setCommonName(string $name): EmailAddressBuilder
    {
        $this->args['commonName'] = $name;
        return new EmailAddressBuilder($this->args);
    }

}

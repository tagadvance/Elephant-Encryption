<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

class EmailAddressBuilder
{
    private array $args;

    public function __construct(array $args)
    {
        $this->args = $args;
    }

    /**
     *
     * @param string $address
     *            e.g. 'goku@intentionallyblankpage.com'
     * @return ArrayBuilder
     */
    public function setEmailAddress(string $address): ArrayBuilder
    {
        $this->args['emailAddress'] = $address;
        return new ArrayBuilder($this->args);
    }

}

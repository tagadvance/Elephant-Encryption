<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

class OrganizationBuilder
{

    private array $args;

    function __construct(array $args)
    {
        $this->args = $args;
    }

    /**
     *
     * @param string $name
     *            e.g. 'Company Name, LLC'
     * @return OrganizationalUnitBuilder
     */
    function setOrganizationName(string $name): OrganizationalUnitBuilder
    {
        $this->args['organizationName'] = $name;
        return new OrganizationalUnitBuilder($this->args);
    }

}

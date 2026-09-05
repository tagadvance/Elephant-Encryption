<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

class OrganizationBuilder
{
    private array $args;

    public function __construct(array $args)
    {
        $this->args = $args;
    }

    /**
     *
     * @param string $name
     *            e.g. 'Company Name, LLC'
     * @return OrganizationalUnitBuilder
     */
    public function setOrganizationName(string $name): OrganizationalUnitBuilder
    {
        $this->args['organizationName'] = $name;
        return new OrganizationalUnitBuilder($this->args);
    }

}

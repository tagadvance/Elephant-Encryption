<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

class OrganizationalUnitBuilder
{

    private array $args;

    function __construct(array $args)
    {
        $this->args = $args;
    }

    /**
     *
     * @param string $name
     *            e.g. 'Development Team' or ''
     * @return CommonBuilder
     */
    function setOrganizationUnitName(string $name): CommonBuilder
    {
        $this->args['organizationalUnitName'] = $name;
        return new CommonBuilder($this->args);
    }

}

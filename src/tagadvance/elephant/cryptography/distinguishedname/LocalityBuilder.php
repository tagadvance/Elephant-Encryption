<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

class LocalityBuilder
{
    private array $args;

    public function __construct(array $args)
    {
        $this->args = $args;
    }

    /**
     *
     * @param string $locality
     *            e.g. 'Medford'
     * @return OrganizationBuilder
     */
    public function setLocality(string $locality): OrganizationBuilder
    {
        $this->args['localityName'] = $locality;
        return new OrganizationBuilder($this->args);
    }

}

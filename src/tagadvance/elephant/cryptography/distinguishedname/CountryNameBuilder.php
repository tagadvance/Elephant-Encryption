<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

class CountryNameBuilder
{

    private array $args;

    function __construct(array $args)
    {
        $this->args = $args;
    }

    /**
     *
     * @param string $countryName
     *            e.g. 'US'
     * @return StateOrProvinceBuilder
     */
    function setCountryName(string $countryName): StateOrProvinceBuilder
    {
        $this->args['countryName'] = $countryName;
        return new StateOrProvinceBuilder($this->args);
    }

}

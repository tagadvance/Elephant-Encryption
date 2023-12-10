<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

class StateOrProvinceBuilder
{

    private array $args;

    function __construct(array $args)
    {
        $this->args = $args;
    }

    /**
     *
     * @param string $name
     *            e.g. 'Oregon'
     * @return LocalityBuilder
     */
    function setStateOrProvinceName(string $name): LocalityBuilder
    {
        $this->args['stateOrProvinceName'] = $name;
        return new LocalityBuilder($this->args);
    }

}

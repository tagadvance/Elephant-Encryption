<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

class ArrayBuilder
{

    private array $args;

    function __construct(array $args)
    {
        $this->args = $args;
    }

    function build(): array
    {
        return $this->args;
    }

}

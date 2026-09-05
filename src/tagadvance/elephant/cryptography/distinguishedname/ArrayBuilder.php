<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

class ArrayBuilder
{
    private array $args;

    public function __construct(array $args)
    {
        $this->args = $args;
    }

    public function build(): array
    {
        return $this->args;
    }

}

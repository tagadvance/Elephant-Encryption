<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

/**
 * Entry point for building a distinguished name.
 *
 * Each setter returns a different builder type, so the compiler enforces both the order and
 * the presence of every field: country, state or province, locality, organization,
 * organizational unit, common name, email address. The last call yields an ArrayBuilder.
 * Pass an ArrayBuilder directly to skip the chain and supply the fields yourself.
 *
 * @author Tag <tagadvance+elephant@gmail.com>
 */
class DistinguishedNameBuilder
{
    /**
     * Starts the chain. Call setCountryName() on the result.
     */
    public static function builder(): CountryNameBuilder
    {
        return new CountryNameBuilder([]);
    }

}

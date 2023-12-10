<?php

namespace tagadvance\elephant\cryptography\distinguishedname;

/**
 *
 * @author Tag <tagadvance+elephant@gmail.com>
 */
class DistinguishedNameBuilder {

    static function builder(): CountryNameBuilder {
        return new CountryNameBuilder([]);
    }

}

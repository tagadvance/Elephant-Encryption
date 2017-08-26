<?php

namespace tagadvance\elephant\cryptography;

/**
 *
 * @author Tag <tagadvance+elephant@gmail.com>
 */
class DistinguishedNameBuilder {

    static function builder(): CountryNameBuilder {
        return new CountryNameBuilder([]);
    }

}

class CountryNameBuilder {

    private $args;

    function __construct(array $args) {
        $this->args = $args;
    }

    /**
     *
     * @param string $countryName
     *            e.g. 'US'
     * @return DistinguishedNameBuilder
     */
    function setCountryName(string $countryName): StateOrProvinceBuilder {
        $this->args['countryName'] = $countryName;
        return new StateOrProvinceBuilder($this->args);
    }

}

class StateOrProvinceBuilder {

    private $args;

    function __construct(array $args) {
        $this->args = $args;
    }

    /**
     *
     * @param string $name
     *            e.g. 'Oregon'
     * @return DistinguishedNameBuilder
     */
    function setStateOrProvinceName(string $name): LocalityBuilder {
        $this->args['stateOrProvinceName'] = $name;
        return new LocalityBuilder($this->args);
    }

}

class LocalityBuilder {

    private $args;

    function __construct(array $args) {
        $this->args = $args;
    }

    /**
     *
     * @param string $locality
     *            e.g. 'Medford'
     * @return DistinguishedNameBuilder
     */
    function setLocality(string $locality): OrganizationBuilder {
        $this->args['localityName'] = $locality;
        return new OrganizationBuilder($this->args);
    }

}

class OrganizationBuilder {

    private $args;

    function __construct(array $args) {
        $this->args = $args;
    }

    /**
     *
     * @param string $name
     *            e.g. 'Company Name, LLC'
     * @return DistinguishedNameBuilder
     */
    function setOrganizationName(string $name): OrganizationalUnitBuilder {
        $this->args['organizationName'] = $name;
        return new OrganizationalUnitBuilder($this->args);
    }

}

class OrganizationalUnitBuilder {

    private $args;

    function __construct(array $args) {
        $this->args = $args;
    }

    /**
     *
     * @param string $name
     *            e.g. 'Development Team' or ''
     * @return DistinguishedNameBuilder
     */
    function setOrganizationUnitName(string $name): CommonBuilder {
        $this->args['organizationalUnitName'] = $name;
        return new CommonBuilder($this->args);
    }

}

class CommonBuilder {

    private $args;

    function __construct(array $args) {
        $this->args = $args;
    }

    /**
     *
     * @param string $name
     *            e.g. 'Son, Goku'
     * @return DistinguishedNameBuilder
     */
    function setCommonName(string $name): EmailAddressBuilder {
        $this->args['commonName'] = $name;
        return new EmailAddressBuilder($this->args);
    }

}

class EmailAddressBuilder {

    private $args;

    function __construct(array $args) {
        $this->args = $args;
    }

    /**
     *
     * @param string $address
     *            e.g. 'goku@intentionallyblankpage.com'
     * @return DistinguishedNameBuilder
     */
    function setEmailAddress(string $address): ArrayBuilder {
        $this->args['emailAddress'] = $address;
        return new ArrayBuilder($this->args);
    }

}

class ArrayBuilder {

    private $args;

    function __construct(array $args) {
        $this->args = $args;
    }

    function build(): array {
        return $this->args;
    }

}
<?php

namespace tagadvance\elephant\cryptography;

use PHPUnit\Framework\TestCase;

class DistinguishedNameBuilderTest extends TestCase {

    function testBuilder() {
        $expected = [
                'countryName' => 'USA',
                'stateOrProvinceName' => 'Oregon',
                'localityName' => 'Crater Lake',
                'organizationName' => 'Acme Corporation',
                'organizationalUnitName' => '',
                'commonName' => 'Wile E. Coyote',
                'emailAddress' => 'w.coyote@acme.com'
        ];
        $dn = DistinguishedNameBuilder::builder()
                ->setCountryName('USA')
                ->setStateOrProvinceName('Oregon')
                ->setLocality('Crater Lake')
                ->setOrganizationName('Acme Corporation')
                ->setOrganizationUnitName('')
                ->setCommonName('Wile E. Coyote')
                ->setEmailAddress('w.coyote@acme.com')
                ->build();
        $this->assertEquals($expected, $dn);
    }

}
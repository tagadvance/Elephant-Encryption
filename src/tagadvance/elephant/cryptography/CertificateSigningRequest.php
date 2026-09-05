<?php

namespace tagadvance\elephant\cryptography;

use OpenSSLCertificateSigningRequest;
use SplFileInfo;
use tagadvance\elephant\cryptography\distinguishedname\ArrayBuilder;

/**
 * A certificate signing request, which sign() turns into a certificate.
 */
class CertificateSigningRequest
{
    private OpenSSLCertificateSigningRequest $csr;

    /**
     * @param ArrayBuilder $builder the distinguished name, from DistinguishedNameBuilder
     * @throws CryptographyException if the request cannot be created
     */
    public static function newCertificateSigningRequest(ArrayBuilder $builder, PrivateKey $privateKey): self
    {
        $dn = $builder->build();
        $key = $privateKey->getKey();
        $csr = OpenSSL::call(
            fn() => openssl_csr_new($dn, $key),
            'could not create certificate signing request',
        );

        return new self($csr);
    }

    private function __construct(OpenSSLCertificateSigningRequest $csr)
    {
        $this->csr = $csr;
    }

    /**
     * Self-signs this request, since no CA certificate is passed.
     *
     * @param int $days how long the certificate stays valid
     * @throws CryptographyException if signing fails
     */
    public function sign(PrivateKey $privateKey, int $days = 365): Certificate
    {
        $certificate = OpenSSL::call(
            fn() => openssl_csr_sign($this->csr, $cacert = null, $privateKey->getKey(), $days),
            'could not sign certificate signing request',
        );

        return new Certificate($certificate);
    }

    /**
     * @param bool $includeHumanReadableInformation prepend the request's fields in plain text
     * @throws CryptographyException if the request cannot be exported
     */
    public function export(bool $includeHumanReadableInformation = false): string
    {
        $out = '';
        OpenSSL::call(
            function () use (&$out, $includeHumanReadableInformation) {
                return openssl_csr_export($this->csr, $out, ! $includeHumanReadableInformation);
            },
            'certificate signing request could not be exported',
        );

        return $out;
    }

    /**
     * @param bool $includeHumanReadableInformation prepend the request's fields in plain text
     * @throws CryptographyException if the file cannot be written
     */
    public function exportToFile(SplFileInfo $file, bool $includeHumanReadableInformation = false): void
    {
        $filePath = $file->getPathname();
        OpenSSL::call(
            fn() => openssl_csr_export_to_file($this->csr, $filePath, ! $includeHumanReadableInformation),
            'certificate signing request could not be saved',
        );
    }

}

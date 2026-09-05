<?php

namespace tagadvance\elephant\cryptography;

use OpenSSLCertificateSigningRequest;
use SplFileInfo;
use tagadvance\elephant\cryptography\distinguishedname\ArrayBuilder;

class CertificateSigningRequest
{
    private OpenSSLCertificateSigningRequest $csr;

    /**
     *
     * @param ArrayBuilder $builder
     * @param PrivateKey $privateKey
     * @throws CryptographyException
     * @return self
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

    /**
     *
     * @param OpenSSLCertificateSigningRequest $csr
     */
    private function __construct(OpenSSLCertificateSigningRequest $csr)
    {
        $this->csr = $csr;
    }

    /**
     *
     * @param PrivateKey $privateKey
     * @param int $days
     * @throws CryptographyException
     * @return Certificate
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
     *
     * @param bool $includeHumanReadableInformation
     * @throws CryptographyException
     * @return string
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
     *
     * @param SplFileInfo $file
     * @param bool $includeHumanReadableInformation
     * @throws CryptographyException
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

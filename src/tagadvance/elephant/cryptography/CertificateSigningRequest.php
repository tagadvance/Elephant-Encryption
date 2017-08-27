<?php

namespace tagadvance\elephant\cryptography;

class CertificateSigningRequest {

    /**
     *
     * @var resource
     */
    private $csr;

    /**
     *
     * @param ArrayBuilder $builder
     * @param PrivateKey $privateKey
     * @throws CryptographyException
     * @return self
     */
    static function newCertificateSigningRequest(ArrayBuilder $builder, PrivateKey $privateKey): self {
        $dn = $builder->build();
        $key = $privateKey->getKey();
        $csr = openssl_csr_new($dn, $key);
        if (is_resource($csr)) {
            return new self($csr);
        }
        throw new CryptographyException('could not create certificate signing request');
    }

    /**
     *
     * @param resource $csr
     */
    private function __construct($csr) {
        $this->csr = $csr;
    }

    /**
     *
     * @param PrivateKey $privateKey
     * @param int $days
     * @throws CryptographyException
     * @return Certificate
     */
    function sign(PrivateKey $privateKey, int $days = 365): Certificate {
        try {
            $certificate = openssl_csr_sign($this->csr, $cacert = null, $privateKey->getKey(), $days);
            if (is_resource($certificate)) {
                return new Certificate($certificate);
            }
        } catch (\Throwable $t) {
            throw new CryptographyException('could not sign certificate signing request', $code = null, $t);
        }
        throw new CryptographyException('could not sign certificate signing request');
    }

    /**
     *
     * @param string $includeHumanReadableInformation
     * @throws CryptographyException
     * @return string
     */
    function export($includeHumanReadableInformation = false): string {
        $out = '';
        $isExported = openssl_csr_export($this->csr, $out, ! $includeHumanReadableInformation);
        if (! $isExported) {
            throw new CryptographyException('certificate signing request could not be exported');
        }
        return $out;
    }

    /**
     *
     * @param \SplFileInfo $file
     * @param string $includeHumanReadableInformation
     * @throws CryptographyException
     */
    function exportToFile(\SplFileInfo $file, $includeHumanReadableInformation = false): void {
        $filePath = $file->getPathname();
        $isExported = openssl_csr_export_to_file($this->csr, $filePath, ! $includeHumanReadableInformation);
        if (! $isExported) {
            throw new CryptographyException('certificate signing request could not be saved');
        }
    }

}
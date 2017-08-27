<?php

namespace tagadvance\elephant\cryptography;

class CertificateSigningRequest {

    /**
     *
     * @var resource
     */
    private $csr;

    static function newCertificateSigningRequest(ArrayBuilder $builder, PrivateKey $privateKey): self {
        $dn = $builder->build();
        $key = $privateKey->getKey();
        $csr = openssl_csr_new($dn, $key);
        return new self($csr);
    }

    function __construct($csr) {
        if (! is_resource($csr)) {
            $message = '$csr must be a resource';
            throw new \InvalidArgumentException($message);
        }
        
        $this->csr = $csr;
    }

    function sign(PrivateKey $privateKey, int $days = 365): Certificate {
        $certificate = openssl_csr_sign($this->csr, $cacert = null, $privateKey->getKey(), $days);
        if ($certificate === false) {
            throw new CryptographyException();
        }
        return new Certificate($certificate);
    }

    function export($includeHumanReadableInformation = false): string {
        $out = '';
        $isExported = openssl_csr_export($this->csr, $out, ! $includeHumanReadableInformation);
        if (! $isExported) {
            throw new CryptographyException('certificate signing request could not be exported');
        }
        return $out;
    }

    function exportToFile(\SplFileInfo $file, $includeHumanReadableInformation = false): void {
        $filePath = $file->getPathname();
        $isExported = openssl_csr_export_to_file($this->csr, $filePath, ! $includeHumanReadableInformation);
        if (! $isExported) {
            throw new CryptographyException('certificate signing request could not be saved');
        }
    }

}
<?php

namespace tagadvance\elephant\cryptography;

use InvalidArgumentException;
use OpenSSLCertificate;
use SplFileInfo;

/**
 * A parsed X.509 certificate.
 */
class Certificate
{
    private OpenSSLCertificate $certificate;

    /**
     * @throws CryptographyException if the file cannot be read as a certificate
     */
    public static function createFromFile(SplFileInfo $file): self
    {
        $path = $file->getRealPath();
        $filePath = "file://$path";
        $certificate = OpenSSL::call(
            fn() => openssl_x509_read($filePath),
            'could not read resource',
        );

        return new self($certificate);
    }

    public function __construct(OpenSSLCertificate $certificate)
    {
        $this->certificate = $certificate;
    }

    public function getCertificate(): OpenSSLCertificate
    {
        return $this->certificate;
    }

    /**
     * @param bool $includeHumanReadableInformation prepend the certificate's fields in plain text
     * @throws CryptographyException if the certificate cannot be exported
     */
    public function export(bool $includeHumanReadableInformation = false): string
    {
        $output = '';
        OpenSSL::call(
            function () use (&$output, $includeHumanReadableInformation) {
                return openssl_x509_export($this->certificate, $output, ! $includeHumanReadableInformation);
            },
            'certificate could not be exported',
        );

        return $output;
    }

    /**
     * @param bool $includeHumanReadableInformation prepend the certificate's fields in plain text
     * @throws CryptographyException if the file cannot be written
     */
    public function exportToFile(SplFileInfo $file, bool $includeHumanReadableInformation = false): void
    {
        $filePath = $file->getPathname();
        OpenSSL::call(
            fn() => openssl_x509_export_to_file($this->certificate, $filePath, ! $includeHumanReadableInformation),
            'certificate could not be saved',
        );
    }

}

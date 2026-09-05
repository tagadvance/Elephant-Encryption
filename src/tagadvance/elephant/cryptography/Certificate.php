<?php

namespace tagadvance\elephant\cryptography;

use InvalidArgumentException;
use OpenSSLCertificate;
use SplFileInfo;

class Certificate
{
    private OpenSSLCertificate $certificate;

    /**
     *
     * @param SplFileInfo $file
     * @throws CryptographyException
     * @return self
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

    /**
     *
     * @param OpenSSLCertificate $certificate
     * @throws InvalidArgumentException
     */
    public function __construct(OpenSSLCertificate $certificate)
    {
        $this->certificate = $certificate;
    }

    public function getCertificate(): OpenSSLCertificate
    {
        return $this->certificate;
    }

    /**
     *
     * @param bool $includeHumanReadableInformation
     * @throws CryptographyException
     * @return string
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
     *
     * @param SplFileInfo $file
     * @param bool $includeHumanReadableInformation
     * @throws CryptographyException
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

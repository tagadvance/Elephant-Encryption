<?php

namespace tagadvance\elephant\cryptography;

use tagadvance\gilligan\io\File;
use tagadvance\gilligan\io\Closeable;

class Certificate implements Closeable {

    /**
     *
     * @var resource
     */
    private $certificate;

    /**
     *
     * @param File $file
     * @throws CryptographyException
     * @return self
     */
    static function createFromFile(\SplFileInfo $file): self {
        $path = $file->getRealPath();
        $filePath = "file://$path";
        $certificate = openssl_x509_read($filePath);
        if (is_resource($certificate)) {
            return new self($certificate);
        }
        throw new CryptographyException('could not read resource');
    }

    /**
     *
     * @param resource $certificate
     * @throws \InvalidArgumentException
     */
    function __construct($certificate) {
        if (! is_resource($certificate)) {
            throw new \InvalidArgumentException('$certificate must be a resource');
        }
        $this->certificate = $certificate;
    }

    /**
     * 
     * @return resource
     */
    function getCertificate() {
        return $this->certificate;
    }

    /**
     *
     * @param string $includeHumanReadableInformation
     * @throws CryptographyException
     * @return string
     */
    function export($includeHumanReadableInformation = false): string {
        $output = '';
        $isExported = openssl_x509_export($this->certificate, $output, ! $includeHumanReadableInformation);
        if ($isExported) {
            return $output;
        }
        throw new CryptographyException();
    }

    /**
     *
     * @param \SplFileInfo $file
     * @param bool $includeHumanReadableInformation
     * @throws CryptographyException
     */
    function exportToFile(\SplFileInfo $file, bool $includeHumanReadableInformation = false): void {
        $filePath = $file->getPathname();
        $isExported = openssl_x509_export_to_file($this->certificate, $filePath, ! $includeHumanReadableInformation);
        if (! $isExported) {
            throw new CryptographyException('certificate could not be saved');
        }
    }

    function close() {
        openssl_x509_free($this->certificate);
    }

}
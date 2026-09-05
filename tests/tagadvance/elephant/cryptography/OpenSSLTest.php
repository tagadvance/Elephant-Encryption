<?php

namespace tagadvance\elephant\cryptography;

use PHPUnit\Framework\TestCase;
use tagadvance\gilligan\io\MemoryOutputStream;
use tagadvance\gilligan\io\PrintStream;

/**
 *
 * @author Tag <tagadvance+elephant@gmail.com>
 */
class OpenSSLTest extends TestCase
{
    public function testClearErrors(): void
    {
        OpenSSL::clearErrors();
        $this->assertFalse(openssl_error_string());
    }

    public function testPrintErrors(): void
    {
        $mos = new MemoryOutputStream();
        $out = new PrintStream($mos);
        OpenSSL::printErrors($out);

        $contents = $mos->getContents();
        $this->assertEmpty($contents);
    }

}

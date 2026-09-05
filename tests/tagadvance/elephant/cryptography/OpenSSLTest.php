<?php

namespace tagadvance\elephant\cryptography;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

/**
 *
 * @author Tag <tagadvance+elephant@gmail.com>
 */
class OpenSSLTest extends TestCase
{
    /**
     * A configuration openssl_pkey_new() rejects. It reports the reason as a PHP warning
     * and leaves the error queue empty.
     *
     * @var array<string, int>
     */
    private const BOGUS_CONFIGURATION = [
        'private_key_bits' => 0,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];

    public function testCallReturnsTheResult(): void
    {
        $result = OpenSSL::call(fn() => openssl_pkey_new(), 'could not create private key');

        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $result);
    }

    public function testCallDescribesFailureFromTheErrorQueue(): void
    {
        $this->expectException(CryptographyException::class);
        $this->expectExceptionMessage('key could not be read: error:');
        OpenSSL::call(fn() => openssl_pkey_get_private('not a key'), 'key could not be read');
    }

    public function testCallFallsBackToThePhpDiagnosticWhenTheQueueIsEmpty(): void
    {
        $this->expectException(CryptographyException::class);
        $this->expectExceptionMessage('Private key length must be at least 384 bits');
        OpenSSL::call(
            fn() => openssl_pkey_new(self::BOGUS_CONFIGURATION),
            'could not create private key',
        );
    }

    public function testCallDoesNotLeakWarningsToTheApplicationErrorHandler(): void
    {
        $leaked = [];
        set_error_handler(function (int $errno, string $error) use (&$leaked): bool {
            $leaked[] = $error;
            return true;
        });

        try {
            OpenSSL::call(fn() => openssl_pkey_new(self::BOGUS_CONFIGURATION), 'could not create private key');
            $this->fail('the call was expected to throw');
        } catch (CryptographyException $e) {
            $this->assertStringContainsString('at least 384 bits', $e->getMessage());
        } finally {
            restore_error_handler();
        }

        $this->assertSame([], $leaked);
    }

    public function testCallDoesNotAttributeStaleErrorsToALaterCall(): void
    {
        // Pollute the process-wide queue the way any other openssl consumer would.
        @openssl_pkey_get_private('not a key');

        try {
            OpenSSL::call(fn() => openssl_pkey_new(self::BOGUS_CONFIGURATION), 'could not create private key');
            $this->fail('the call was expected to throw');
        } catch (CryptographyException $e) {
            $this->assertStringNotContainsString('DECODER', $e->getMessage());
            $this->assertSame([], $e->getOpenSSLErrors());
        }
    }

    public function testOpenSSLErrorsAreAvailableAsStructuredDetail(): void
    {
        try {
            OpenSSL::call(fn() => openssl_pkey_get_private('not a key'), 'key could not be read');
            $this->fail('the call was expected to throw');
        } catch (CryptographyException $e) {
            $errors = $e->getOpenSSLErrors();
            $this->assertNotEmpty($errors);
            $this->assertStringContainsString('error:', $errors[0]);
        }
    }

}

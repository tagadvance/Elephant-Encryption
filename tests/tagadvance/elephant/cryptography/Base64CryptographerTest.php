<?php

namespace tagadvance\elephant\cryptography;

use LogicException;
use PHPUnit\Framework\TestCase;

class Base64CryptographerTest extends TestCase
{
    public function testDecryptRejectsInvalidBase64(): void
    {
        $cryptographer = Base64Cryptographer::create($this->newUnreachableDelegate());

        $this->expectException(CryptographyException::class);
        $this->expectExceptionMessage('input is not valid base64');
        $cryptographer->decrypt('!!!!not base64!!!!');
    }

    public function testRoundTripOfValidBase64(): void
    {
        $delegate = new class implements Cryptographer {
            public function encrypt(string $data): string
            {
                return strrev($data);
            }

            public function decrypt(string $data): string
            {
                return strrev($data);
            }
        };

        $cryptographer = Base64Cryptographer::create($delegate);

        $encrypted = $cryptographer->encrypt('attack at dawn');
        $this->assertSame('bndhZCB0YSBrY2F0dGE=', $encrypted);
        $this->assertSame('attack at dawn', $cryptographer->decrypt($encrypted));
    }

    private function newUnreachableDelegate(): Cryptographer
    {
        return new class implements Cryptographer {
            public function encrypt(string $data): string
            {
                throw new LogicException('the delegate must not be reached');
            }

            public function decrypt(string $data): string
            {
                throw new LogicException('the delegate must not be reached');
            }
        };
    }

}

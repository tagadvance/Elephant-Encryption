<?php

namespace tagadvance\elephant\cryptography;

interface Cryptographer {

    function encrypt(string $data): string;

    function decrypt(string $data): string;

}
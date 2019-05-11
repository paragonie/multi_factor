<?php
declare(strict_types=1);
namespace ParagonIE\MultiFactor\OTP;

use ParagonIE\HiddenString\HiddenString;

/**
 * Interface OTPInterface
 * @package ParagonIE\MultiFactor\OTP
 */
interface OTPInterface
{
    /**
     * Get the code we need
     *
     * @param string|HiddenString $sharedSecret The key to use for determining the TOTP
     * @param int $counterValue    Current time or HOTP counter
     * @return string
     * @throws \OutOfRangeException
     */
    public function getCode(
        $sharedSecret,
        int $counterValue
    ): string;

    public function getLength(): int;
}

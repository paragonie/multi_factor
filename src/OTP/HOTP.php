<?php
declare(strict_types=1);
namespace ParagonIE\MultiFactor\OTP;

use ParagonIE\ConstantTime\{
    Binary,
    Hex
};
use ParagonIE\HiddenString\HiddenString;

/**
 * Class HOTP
 * @package ParagonIE\MultiFactor\OTP
 */
class HOTP implements OTPInterface
{
    protected string $algo;
    protected int $length;

    /**
     * @param int $length          How many digits should each HOTP be?
     * @param string $algo         Hash function to use
     */
    public function __construct(int $length = 6, string $algo = 'sha1')
    {
        $this->length = $length;
        $this->algo = $algo;
    }

    /**
     * Generate a HOTP secret in accordance with RFC 4226
     *
     * @ref https://tools.ietf.org/html/rfc4226
     * @param string|HiddenString $sharedSecret The key to use for determining the HOTP
     * @param int $counterValue    Current time or HOTP counter
     * @return string
     * @throws \OutOfRangeException
     */
    public function getCode($sharedSecret, int $counterValue): string
    {
        $key = is_string($sharedSecret) ? $sharedSecret : $sharedSecret->getString();
        $msg = $this->getTValue($counterValue);
        return self::generateHOTPValue($this->length, $key, $this->algo, $msg);
    }

    public function getLength(): int
    {
        return $this->length;
    }

    /**
     * Get the binary T value
     */
    protected function getTValue(int $counter): string
    {
        $hex = \str_pad(
            \dechex($counter),
            16,
            '0',
            STR_PAD_LEFT
        );

        return Hex::decode($hex);
    }

    /**
     * @internal
     * @ref https://tools.ietf.org/html/rfc4226
     */
    public static function generateHOTPValue(int $length, string $key, string $algo, string $data): string
    {
        if ($length < 1 || $length > 10) {
            throw new \OutOfRangeException(
                'Length must be between 1 and 10, as a consequence of RFC 6238.'
            );
        }

        $bytes = \hash_hmac($algo, $data, $key, true);
        $byteLen = Binary::safeStrlen($bytes);

        // Per the RFC
        /** @var int $offset */
        $offset = \unpack('C', $bytes[$byteLen - 1])[1];
        $offset &= 0x0f;

        /** @var array{0: int, 1: int, 2: int, 3: int} $unpacked */
        $unpacked = \array_values(
            \unpack('C*', Binary::safeSubstr($bytes, $offset, 4))
        );

        $intValue = (
            (($unpacked[0] & 0x7f) << 24)
            | (($unpacked[1] & 0xff) << 16)
            | (($unpacked[2] & 0xff) <<  8)
            | (($unpacked[3] & 0xff)      )
        );

        $intValue %= 10 ** $length;

        return \str_pad(
            (string) $intValue,
            $length,
            '0',
            \STR_PAD_LEFT
        );
    }
}

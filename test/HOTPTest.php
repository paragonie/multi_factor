<?php
declare(strict_types=1);

use ParagonIE\ConstantTime\Hex;
use ParagonIE\MultiFactor\OTP\HOTP;
use PHPUnit\Framework\TestCase;

/**
 * Class HOTPTest
 */
class HOTPTest extends TestCase
{
    /**
     * Test vectors from RFC 6238
     */
    public function testTOTP(): void
    {
        $seed = Hex::decode(
            "3132333435363738393031323334353637383930"
        );
        $hotp = new HOTP();

        $this->assertSame('755224', $hotp->getCode($seed, 0));
        $this->assertSame('287082', $hotp->getCode($seed, 1));
        $this->assertSame('359152', $hotp->getCode($seed, 2));
        $this->assertSame('969429', $hotp->getCode($seed, 3));
        $this->assertSame('338314', $hotp->getCode($seed, 4));
        $this->assertSame('254676', $hotp->getCode($seed, 5));
        $this->assertSame('287922', $hotp->getCode($seed, 6));
        $this->assertSame('162583', $hotp->getCode($seed, 7));
        $this->assertSame('399871', $hotp->getCode($seed, 8));
        $this->assertSame('520489', $hotp->getCode($seed, 9));
    }

    /**
     * @dataProvider dataProviderFailureOfGetCode
     *
     * @psalm-param class-string<\Throwable> $expectedException
     */
    public function testFailureOfGetCode(
        int $length,
        string $expectedException,
        string $expectedExceptionMessage,
        string $sharedSecret,
        int $counterValue
    ): void {
        $hotp = new HOTP($length);

        $this->assertSame($length, $hotp->getLength());

        $this->expectException($expectedException);
        $this->expectExceptionMessage($expectedExceptionMessage);

        $hotp->getCode($sharedSecret, $counterValue);
    }

    /**
     * @psalm-return array<int, array{0:int, 1:class-string<\Throwable>, 2:string, 3:string, 4:int}>
     */
    public function dataProviderFailureOfGetCode(): array
    {
        $seed = Hex::decode(
            "3132333435363738393031323334353637383930"
        );

        return [
            [
                0,
                \OutOfRangeException::class,
                'Length must be between 1 and 10, as a consequence of RFC 6238.',
                $seed,
                0,
            ],
            [
                11,
                \OutOfRangeException::class,
                'Length must be between 1 and 10, as a consequence of RFC 6238.',
                $seed,
                0,
            ],
        ];
    }
}

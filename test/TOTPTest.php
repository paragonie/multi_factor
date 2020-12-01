<?php
declare(strict_types=1);

use ParagonIE\ConstantTime\Hex;
use ParagonIE\MultiFactor\OneTime;
use ParagonIE\MultiFactor\OTP\TOTP;
use PHPUnit\Framework\TestCase;

/**
 * Class TOTPTest
 */
class TOPTTest extends TestCase
{
    /**
     * Test vectors from RFC 6238
     */
    public function testTOTP(): void
    {
        $seed = Hex::decode(
            "3132333435363738393031323334353637383930"
        );
        $seed32 = Hex::decode(
            "3132333435363738393031323334353637383930" .
            "313233343536373839303132"
        );
        // Seed for HMAC-SHA512 - 64 bytes
        $seed64 = Hex::decode(
            "3132333435363738393031323334353637383930" .
            "3132333435363738393031323334353637383930" .
            "3132333435363738393031323334353637383930" .
            "31323334"
        );

        /**
        * @psalm-var array<int, array{time:int, outputs:array{sha1:string, sha256:string, sha512:string}}>
        */
        $testVectors = [
            [
                'time' =>
                    59,
                'outputs' => [
                    'sha1' =>
                        '94287082',
                    'sha256' =>
                        '46119246',
                    'sha512' =>
                        '90693936'
                ]
            ], [
                'time' =>
                    1111111109,
                'outputs' => [
                    'sha1' =>
                        '07081804',
                    'sha256' =>
                        '68084774',
                    'sha512' =>
                        '25091201'
                ]
            ], [
                'time' =>
                    1111111111,
                'outputs' => [
                    'sha1' =>
                        '14050471',
                    'sha256' =>
                        '67062674',
                    'sha512' =>
                        '99943326'
                ]
            ], [
                'time' =>
                    1234567890,
                'outputs' => [
                    'sha1' =>
                        '89005924',
                    'sha256' =>
                        '91819424',
                    'sha512' =>
                        '93441116'
                ]
            ], [
                'time' =>
                    2000000000,
                'outputs' => [
                    'sha1' =>
                        '69279037',
                    'sha256' =>
                        '90698825',
                    'sha512' =>
                        '38618901'
                ]
            ]
        ];
        if (PHP_INT_SIZE > 4) {
            /**
            * @var int
            */
            $intFor64SystemOnly = 20000000000;

            // 64-bit systems only:
            $testVectors[] = [
                'time' =>
                    $intFor64SystemOnly,
                'outputs' => [
                    'sha1' =>
                        '65353130',
                    'sha256' =>
                        '77737706',
                    'sha512' =>
                        '47863826'
                ]
            ];
        }

        $sha1 = new TOTP(0, 30, 8, 'sha1');
        $sha256 = new TOTP(0, 30, 8, 'sha256');
        $sha512 = new TOTP(0, 30, 8, 'sha512');

        foreach ($testVectors as $test) {
            $this->assertSame(
                $test['outputs']['sha1'],
                $sha1->getCode($seed, $test['time']),
                (string) $test['time']
            );

            $this->assertSame(
                $test['outputs']['sha256'],
                $sha256->getCode($seed32, $test['time']),
                (string) $test['time']
            );

            $this->assertSame(
                $test['outputs']['sha512'],
                $sha512->getCode($seed64, $test['time']),
                (string) $test['time']
            );

            $oneTimeSha1 = new OneTime($seed, $sha1);
            $oneTimeSha256 = new OneTime($seed32, $sha256);
            $oneTimeSha512 = new OneTime($seed64, $sha512);

            $this->assertSame(
                $test['outputs']['sha1'],
                $oneTimeSha1->generateCode($test['time']),
                (string) $test['time']
            );
            $this->assertTrue(
                $oneTimeSha1->validateCode($test['outputs']['sha1'], $test['time'])
            );

            $this->assertSame(
                $test['outputs']['sha256'],
                $oneTimeSha256->generateCode($test['time']),
                (string) $test['time']
            );
            $this->assertTrue(
                $oneTimeSha256->validateCode($test['outputs']['sha256'], $test['time'])
            );

            $this->assertSame(
                $test['outputs']['sha512'],
                $oneTimeSha512->generateCode($test['time']),
                (string) $test['time']
            );
            $this->assertTrue(
                $oneTimeSha512->validateCode($test['outputs']['sha512'], $test['time'])
            );
        }
    }

    /**
     * @dataProvider dataProviderFailureOfGetCode
     *
     * @param array{0:int, 1:int, 2:int, 3:string} $constructorArgs
     *
     * @psalm-param class-string<\Throwable> $expectedException
     */
    public function testFailureOfGetCode(
        array $constructorArgs,
        string $expectedException,
        string $expectedExceptionMessage,
        string $sharedSecret,
        int $counterValue
    ): void {
        $totp = new TOTP(...$constructorArgs);

        $this->assertSame($constructorArgs[2], $totp->getLength());
        $this->assertSame($constructorArgs[1], $totp->getTimeStep());

        $this->expectException($expectedException);
        $this->expectExceptionMessage($expectedExceptionMessage);

        $totp->getCode($sharedSecret, $counterValue);
    }

    /**
     * @psalm-return Generator<int, array{0:array{0:int, 1:int, 2:int, 3:string}, 1:class-string<\Throwable>, 2:string, 3:string, 4:int}, mixed, void>
     */
    public function dataProviderFailureOfGetCode(): \Generator
    {
        $seed = Hex::decode(
            "3132333435363738393031323334353637383930"
        );
        $seed32 = Hex::decode(
            "3132333435363738393031323334353637383930" .
            "313233343536373839303132"
        );
        // Seed for HMAC-SHA512 - 64 bytes
        $seed64 = Hex::decode(
            "3132333435363738393031323334353637383930" .
            "3132333435363738393031323334353637383930" .
            "3132333435363738393031323334353637383930" .
            "31323334"
        );

        $sha1 = [0, 30, 8, 'sha1'];
        $sha256 = [0, 30, 8, 'sha256'];
        $sha512 = [0, 30, 8, 'sha512'];

        $times = [
            59,
            1111111109,
            1111111111,
            1234567890,
            2000000000,
        ];

        if (PHP_INT_SIZE > 4) {
            $intFor64SystemOnly = 20000000000;

            $times[] = $intFor64SystemOnly;
        }

        $badLengthArgs = [
            0,
            11,
        ];

        foreach ($times as $time) {
            foreach ($badLengthArgs as $badLength) {
                $sha1[2] = $badLength;
                $sha256[2] = $badLength;
                $sha512[2] = $badLength;

                yield [
                    $sha1,
                    \OutOfRangeException::class,
                    'Length must be between 1 and 10, as a consequence of RFC 6238.',
                    $seed,
                    $time,
                ];
                yield [
                    $sha256,
                    \OutOfRangeException::class,
                    'Length must be between 1 and 10, as a consequence of RFC 6238.',
                    $seed32,
                    $time,
                ];
                yield [
                    $sha512,
                    \OutOfRangeException::class,
                    'Length must be between 1 and 10, as a consequence of RFC 6238.',
                    $seed64,
                    $time,
                ];
            }
        }
    }
}

<?php
declare(strict_types=1);

use \BaconQrCode\Writer;
use \BaconQrCode\Renderer\PlainTextRenderer;
use \ParagonIE\ConstantTime\Hex;
use \ParagonIE\MultiFactor\OTP\HOTP;
use \ParagonIE\MultiFactor\OTP\TOTP;
use \ParagonIE\MultiFactor\Vendor\GoogleAuth;
use \PHPUnit\Framework\TestCase;

class GoogleAuthTest extends TestCase
{
    /**
     * @psalm-return Generator<int, array{0:string, 1:string, 2:string, 3:string, 4:int, 5:GoogleAuth, 6:Writer|null}>
     */
    public function dataProviderMakeQRCodeMessage() : Generator
    {
        $seed = Hex::decode(
            "3132333435363738393031323334353637383930"
        );

        // Seed for HMAC-SHA512 - 64 bytes
        $seed64 = Hex::decode(
            "3132333435363738393031323334353637383930" .
            "3132333435363738393031323334353637383930" .
            "3132333435363738393031323334353637383930" .
            "31323334"
        );

        $sha512 = new TOTP(0, 30, 8, 'sha512');

        $googleAuths = [
            HOTP::class => new GoogleAuth($seed, new HOTP()),
            TOTP::class => new GoogleAuth($seed64, $sha512),
        ];

        $writers = [
            null,
            new Writer(new PlainTextRenderer()),
        ];

        foreach ($writers as $writer) {
            yield [
                'otpauth://totp/?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojqgezdgnbvgy3tqojqgezdgnbvgy3tqojqgezdgnbvgy3tqojqgezdgnbvgy3tqojqgezdgna%3D&digits=8&period=30',
                '',
                '',
                '',
                0,
                $googleAuths[TOTP::class],
                $writer,
            ];

            yield [
                'otpauth://hotp/?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&digits=6&counter=0',
                '',
                '',
                '',
                0,
                $googleAuths[HOTP::class],
                $writer,
            ];

            yield [
                'otpauth://totp/baz:foo%40example.com?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojqgezdgnbvgy3tqojqgezdgnbvgy3tqojqgezdgnbvgy3tqojqgezdgnbvgy3tqojqgezdgna%3D&issuer=bar&digits=8&period=30',
                'foo@example.com',
                'bar',
                'baz',
                1,
                $googleAuths[TOTP::class],
                $writer,
            ];

            yield [
                'otpauth://hotp/baz:foo%40example.com?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&issuer=bar&digits=6&counter=1',
                'foo@example.com',
                'bar',
                'baz',
                1,
                $googleAuths[HOTP::class],
                $writer,
            ];
        }
    }

    /**
    * @dataProvider dataProviderMakeQRCodeMessage
    */
    public function testMakeQRCodeMessage(
        string $message,
        string $username,
        string $issuer,
        string $label,
        int $initialCounter,
        GoogleAuth $googleAuth,
        ?Writer $writer
    ): void {
        $this->assertSame(
            $message,
            $googleAuth->makeQRCodeMessage($username, $issuer, $label, $initialCounter)
        );

        if (!is_null($writer)) {
            $fixture = __DIR__ . '/fixtures/' . hash('sha512', $message) . '.qrcode.txt';

            if (is_file($fixture)) {
                $this->assertSame(
                    file_get_contents($fixture),
                    $googleAuth->getQRCode($writer, $username, $issuer, $label, $initialCounter)
                );
            } else {
                static::generateQrCodeFixture(
                    $username,
                    $issuer,
                    $label,
                    $initialCounter,
                    $googleAuth,
                    $writer
                );
            }
        }
    }

    protected static function generateQrCodeFixture(
        string $username,
        string $issuer,
        string $label,
        int $initialCounter,
        GoogleAuth $googleAuth,
        Writer $writer
    ): void {
        $message = $googleAuth->makeQRCodeMessage(
            $username,
            $issuer,
            $label,
            $initialCounter
        );

        $googleAuth->makeQRCode(
            $writer,
            (__DIR__ . '/fixtures/' . hash('sha512', $message) . '.qrcode.txt'),
            $username,
            $issuer,
            $label,
            $initialCounter
        );
    }
}

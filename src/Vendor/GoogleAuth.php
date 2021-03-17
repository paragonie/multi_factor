<?php
declare(strict_types=1);
namespace ParagonIE\MultiFactor\Vendor;

use BaconQrCode\Renderer\Image\ImagickImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use \BaconQrCode\Writer;
use \ParagonIE\ConstantTime\Base32;
use ParagonIE\MultiFactor\OneTime;
use \ParagonIE\MultiFactor\OTP\{
    HOTP,
    TOTP
};

/**
 * Class GoogleAuth
 * @package ParagonIE\MultiFactor\Vendor
 */
class GoogleAuth extends OneTime
{
    public int $defaultQRCodeSize = 384;

    /**
     * Create a QR code to load the key onto the device
     *
     * @param Writer $qrCodeWriter
     * @param string $outFile        Where to store the QR code?
     * @param string $username       Username or email address
     * @param string $issuer         Optional
     * @param string $label          Optional
     * @param int $initialCounter    Initial counter value
     * @return void
     * @throws \Exception
     */
    public function makeQRCode(
        Writer $qrCodeWriter = null,
        string $outFile = 'php://output',
        string $username = '',
        string $issuer = '',
        string $label = '',
        int $initialCounter = 0
    ): void {
        $message = $this->makeQRCodeMessage($username, $issuer, $label, $initialCounter);

        $this->makeQRCodeWriteOrDefault($qrCodeWriter)->writeFile($message, $outFile);
    }

    public function getQRCode(
        Writer $qrCodeWriter = null,
        string $username = '',
        string $issuer = '',
        string $label = '',
        int $initialCounter = 0
    ): string {
        $message = $this->makeQRCodeMessage($username, $issuer, $label, $initialCounter);

        return $this->makeQRCodeWriteOrDefault($qrCodeWriter)->writeString($message);
    }

    public function makeQRCodeMessage(
        string $username = '',
        string $issuer = '',
        string $label = '',
        int $initialCounter = 0
    ): string {
        if ($this->otp instanceof TOTP) {
            $message = 'otpauth://totp/';
        } elseif ($this->otp instanceof HOTP) {
            $message = 'otpauth://hotp/';
        } else {
            throw new \Exception('Not implemented');
        }
        if ($label) {
            $message .= \urlencode(
                \str_replace(':', '', $label)
            );
            $message .= ':';
        }
        $message .= \urlencode($username);
        $args = [
            'secret' => Base32::encode($this->secretKey->getString())
        ];
        if ($issuer) {
            $args['issuer'] = $issuer;
        }
        $args['digits'] = $this->otp->getLength();
        if ($this->otp instanceof TOTP) {
            $args['period'] = $this->otp->getTimeStep();
        } else {
            $args['counter'] = $initialCounter;
        }
        $message .= '?' . \http_build_query($args);

        return $message;
    }

    protected function makeQRCodeWriteOrDefault(Writer $qrCodeWriter = null) : Writer
    {
        // Sane default; You can dependency-inject a replacement:
        if (!$qrCodeWriter) {
            $renderer = new ImageRenderer(
                new RendererStyle($this->defaultQRCodeSize),
                new ImagickImageBackEnd()
            );
            $qrCodeWriter = new Writer($renderer);
        }

        return $qrCodeWriter;
    }
}

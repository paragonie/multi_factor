<?php
declare(strict_types=1);
namespace ParagonIE\MultiFactor;

use ParagonIE\MultiFactor\OTP\{
    OTPInterface,
    TOTP
};
use ParagonIE\HiddenString\HiddenString;

/**
 * Class OneTime
 *
 * @package ParagonIE\MultiFactor
 */
class OneTime implements MultiFactorInterface
{
    /**
     * @var OTPInterface
     */
    protected $otp;

    /**
     * @var HiddenString
     */
    protected $secretKey;

    /**
     * FIDOU2F constructor.
     *
     * @param string|HiddenString $secretKey
     * @param OTPInterface|null $otp
     */
    public function __construct(
        $secretKey = '',
        ?OTPInterface $otp = null
    ) {
        $this->secretKey = ($secretKey instanceof HiddenString) ? $secretKey : new HiddenString($secretKey);
        if (!$otp) {
            $otp = new TOTP();
        }
        $this->otp = $otp;
    }

    /**
     * Generate a TOTP code for 2FA
     */
    public function generateCode(int $counterValue = 0): string
    {
        return $this->otp->getCode(
            $this->secretKey,
            $counterValue
        );
    }

    /**
     * Validate a user-provided code
     */
    public function validateCode(string $code, int $counterValue = 0): bool
    {
        $expected = $this->generateCode($counterValue);
        return \hash_equals($code, $expected);
    }
}

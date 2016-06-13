<?php
declare(strict_types=1);
namespace ParagonIE\MultiFactor;

use ParagonIE\MultiFactor\Traits\TOTP;

/**
 * Class FIDOU2F
 *
 * Implementation for the FIDO Alliance's U2F standard
 *
 * @package ParagonIE\MultiFactor
 */
class FIDOU2F implements MultiFactorInterface
{
    use TOTP;

    /**
     * @var string
     */
    protected $algo;

    /**
     * @var int
     */
    protected $length;

    /**
     * @var string
     */
    private $secretKey;

    /**
     * @var int
     */
    protected $startTime;

    /**
     * @var int
     */
    protected $timeStep;

    /**
     * FIDOU2F constructor.
     *
     * @param string $secretKey
     * @param int $startTime
     * @param int $timeStep
     * @param int $length
     * @param string $algo
     */
    public function __construct(
        string $secretKey = '',
        int $startTime = 0,
        int $timeStep = 30,
        int $length = 6,
        string $algo = 'sha1'
    ) {
        $this->secretKey = $secretKey;
        $this->startTime = $startTime;
        $this->timeStep = $timeStep;
        $this->length = $length;
        $this->algo = $algo;
    }

    /**
     * Generate a TOTP code for 2FA
     *
     * @param int $offset - How many steps backwards to count?
     * @return string
     */
    public function generateCode(int $offset = 0): string
    {
        return $this->getTOTPCode(
            $this->secretKey,
            \time() - ($this->timeStep * $offset),
            $this->startTime,
            $this->timeStep,
            $this->length,
            $this->algo
        );
    }

    /**
     * Validate a user-provided code
     *
     * @param string $code
     * @param int $offset - How many steps backwards to count?
     * @return bool
     */
    public function validateCode(string $code, int $offset = 0): bool
    {
        $expected = $this->generateCode($offset);
        return \hash_equals($code, $expected);
    }
}

<?php
declare(strict_types=1);

namespace ParagonIE\MultiFactor;

/**
 * Interface MultiFactorInterface
 *
 * All MFA solutions should implement this interface.
 *
 * @package ParagonIE\MultiFactor
 */
interface MultiFactorInterface
{
    /**
     * This should return a one-time password the user should enter.
     */
    public function generateCode(): string;

    /**
     * This should validate a code for a particular user.
     */
    public function validateCode(string $code): bool;
}

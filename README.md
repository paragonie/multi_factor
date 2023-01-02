# Multi-Factor

Designed to be a vendor-agnostic implementation of various Two-Factor 
Authentication solutions.

Developed by [Paragon Initiative Enterprises](https://paragonie.com) for use
in our own projects. It's released under a dual license: GPL and MIT. As with
all dual-licensed projects, feel free to choose the license that fits your
needs.

## Requirements

* PHP 7.4+
  * As per [Paragon Initiative Enterprise's commitment to open source](https://paragonie.com/blog/2016/04/go-php-7-our-commitment-maintaining-our-open-source-projects),
    all new software will no longer be written for PHP 5.

## Installing

```sh
composer require paragonie/multi-factor
```

## Example Usage

### Display QR code

```php
<?php
use ParagonIE\MultiFactor\Vendor\GoogleAuth;

$seed = random_bytes(20);
$auth = new GoogleAuth($seed);
$auth->makeQRCode(null, 'php://output', 'email@example.com', 'Issuer', 'Label');
```

### Validate two-factor code

```php
<?php
use ParagonIE\MultiFactor\OneTime;
use ParagonIE\MultiFactor\OTP\TOTP;

// You can use TOTP or HOTP
$otp = new OneTime($seed, new TOTP());

if (\password_verify($_POST['password'], $storedHash)) {
    if ($otp->validateCode($_POST['2facode'], time())) {
        // Login successful    
    }
}
```

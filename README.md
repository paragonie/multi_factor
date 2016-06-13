# Multi-Factor

Designed to be a vendor-agnostic implementation of various Two-Factor 
Authentication solutions.

Developed by [Paragon Initiatve Enterprises](https://paragonie.com) for use
in our own projects.

## Requirements

* PHP 7

## Example Usage

```php
<?php
use ParagonIE\MuiltiFactor\FIDOU2F;

$seed = random_bytes(20);

$fido = new FIDOU2F($seed);

if (\password_verify($_POST['password'])) {
    if ($fido->validateCode($_POST['2facode'])) {
        // Login successful    
    }
}
```
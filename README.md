# jwt
JWT tools

## Installation
This component can be installed with the [Composer](https://getcomposer.org/) dependency manager.

1. [Install Composer](https://getcomposer.org/doc/00-intro.md)

2. Install the component as a dependency of your project

        composer require free2er/jwt

## Usage

Create JWK
```php
use Free2er\Jwt\KeyFactory;

$factory = new KeyFactory();
$factory->create('/path/to/private.key');
$factory->create('/path/to/public.key');
```

Create JWT
```php
use Free2er\Jwt\TokenFactory;

$factory = new TokenFactory();
$factory->create(['aud' => 'client', 'sub' => 'user'], '/path/to/private.key');
```

Validate JWT
```php
use Free2er\Jwt\TokenValidator;

$validator = new TokenValidator();
$validator->validate('some.jwt.token', '/path/to/public.key');
```

## OpenSSL commands 

Generate RSA keys
```shell script
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.key
```

Generate RSA keys with password
```shell script
openssl genrsa -passout pass:_passphrase_ -out private.key 2048
openssl rsa -in private.key -passin pass:_passphrase_ -pubout -out public.key
```

Generate EC P-256 keys
```shell script
openssl ecparam -name prime256v1 -genkey -noout -out private.key
openssl ec -in private.key -pubout -out public.key
```

Generate EC P-384 keys 
```shell script
openssl ecparam -name secp384r1 -genkey -noout -out private.key
openssl ec -in private.key -pubout -out public.key
```

Generate EC P-521 keys 
```shell script
openssl ecparam -name secp521r1 -genkey -noout -out private.key
openssl ec -in private.key -pubout -out public.key
```

Generate Ed25519 keys
```shell script
openssl genpkey -algorithm Ed25519 -out private.key
openssl pkey -in private.key -pubout -out public.key
```

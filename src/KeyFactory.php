<?php

declare(strict_types=1);

namespace Free2er\Jwt;

use Base64Url\Base64Url;
use Free2er\Ed25519\Key as Ed25519Factory;
use Free2er\Jwt\Exception\KeyException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\PS512;
use Throwable;

/**
 * Фабрика JWK
 */
class KeyFactory
{
    /**
     * Ключ по умолчанию
     *
     * @var JWK
     */
    private JWK $defaultKey;

    /**
     * Возвращает допустимые алгоритмы шифрования
     *
     * @return AlgorithmManager
     */
    public static function algorithms(): AlgorithmManager
    {
        return new AlgorithmManager([
            new None(),
            new HS256(),
            new HS384(),
            new HS512(),
            new PS512(),
            new ES512(),
            new EdDSA(),
        ]);
    }

    /**
     * Конструктор
     *
     * @param JWK|null $defaultKey
     */
    public function __construct(JWK $defaultKey = null)
    {
        $this->defaultKey = $defaultKey ?: JWKFactory::createNoneKey();
    }

    /**
     * Создает JWK
     *
     * @param string|null $key
     * @param string|null $password
     *
     * @return JWK
     *
     * @throws KeyException
     */
    public function create(string $key = null, string $password = null): JWK
    {
        if ($key === null) {
            return $this->defaultKey;
        }

        if (!$openssl = openssl_pkey_get_private($key, (string) $password)) {
            $openssl = openssl_pkey_get_public($key);
        }

        if ($openssl === false) {
            return $this->createHmacKey($key);
        }

        $type = openssl_pkey_get_details($openssl) ?? null;
        openssl_pkey_free($openssl);

        try {
            switch ($type) {
                case OPENSSL_KEYTYPE_RSA:
                    return $this->createRsaKey($key, $password);

                case OPENSSL_KEYTYPE_EC:
                    return $this->createEcKey($key, $password);
            }
        } catch (Throwable $exception) {
            throw KeyException::wrap($exception);
        }

        try {
            return $this->createEd25519Key($key);
        } catch (Throwable $exception) {
            return $this->createHmacKey($key);
        }
    }

    /**
     * Создает ключ HMAC
     *
     * @param string $secret
     *
     * @return JWK
     */
    private function createHmacKey(string $secret): JWK
    {
        $length = strlen($secret);

        switch (true) {
            case $length >= 64:
                $algorithm = 'HS512';
                break;

            case $length >= 48:
                $algorithm = 'HS384';
                break;

            default:
                $algorithm = 'HS256';
                break;
        }

        return JWKFactory::createFromSecret($secret, ['alg' => $algorithm]);
    }

    /**
     * Создает ключ RSA
     *
     * @param string      $key
     * @param string|null $password
     *
     * @return JWK
     */
    private function createRsaKey(string $key, string $password = null): JWK
    {
        return JWKFactory::createFromKey($key, $password, ['alg' => 'PS512']);
    }

    /**
     * Создает ключ EC
     *
     * @param string      $key
     * @param string|null $password
     *
     * @return JWK
     */
    private function createEcKey(string $key, string $password = null): JWK
    {
        return JWKFactory::createFromKey($key, $password, ['alg' => 'ES512']);
    }

    /**
     * Создает ключ Ed25519
     *
     * @param string $key
     *
     * @return JWK|null
     */
    private function createEd25519Key(string $key): ?JWK
    {
        $key = Ed25519Factory::createFromKey($key);

        $d = $key->getPrivateKey();
        $x = $key->getPublicKey();

        return new JWK([
            'kty' => 'OKP',
            'alg' => 'EdDSA',
            'crv' => 'Ed25519',
            'd'   => $d ? Base64Url::encode($d) : null,
            'x'   => Base64Url::encode($x),
        ]);
    }
}

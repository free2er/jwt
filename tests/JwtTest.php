<?php

declare(strict_types=1);

namespace Free2er\Jwt;

use Base64Url\Base64Url;
use Carbon\Carbon;
use DateTimeInterface;
use Free2er\Jwt\Exception\ValidatorException;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * Тест JWT
 */
class JwtTest extends TestCase
{
    /**
     * Состав ключа
     *
     * @var array|null
     */
    private ?array $payload;

    /**
     * Текущее время
     *
     * @var DateTimeInterface|null
     */
    private ?DateTimeInterface $now;

    /**
     * Фабрика JWK
     *
     * @var KeyFactory|null
     */
    private ?KeyFactory $keyFactory;

    /**
     * Фабрика JWT
     *
     * @var TokenFactory|null
     */
    private ?TokenFactory $tokenFactory;

    /**
     * Валидатор JWT
     *
     * @var TokenValidator|null
     */
    private ?TokenValidator $tokenValidator;

    /**
     * Инициализирует окружение перез запуском теста
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::now();
        Carbon::setTestNow($this->now);

        $this->payload = [
            'aud' => 'application',
            'sub' => 'user',
            'iat' => $this->now->getTimestamp(),
            'nbf' => $this->now->getTimestamp(),
            'exp' => $this->now->getTimestamp() + 3600,
            'ext' => ['test'],
        ];

        $this->keyFactory     = new KeyFactory();
        $this->tokenFactory   = new TokenFactory();
        $this->tokenValidator = new TokenValidator();
    }

    /**
     * Очищает окружение после завершения теста
     */
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->now = null;
        Carbon::setTestNow(null);

        $this->payload        = null;
        $this->keyFactory     = null;
        $this->tokenFactory   = null;
        $this->tokenValidator = null;
    }

    /**
     * Проверяет JWT без подписи
     */
    public function testNoneToken(): void
    {
        $token = $this->tokenFactory->create($this->payload);
        $this->tokenValidator->validate($token);

        $this->assertPayload($this->payload, $token);
        $this->assertHeader('typ', 'JWT', $token);
        $this->assertHeader('alg', 'none', $token);
    }

    /**
     * Проверяет JWT с подписью HMAC
     *
     * @param string $secret
     * @param string $algorithm
     *
     * @dataProvider provideHmacKeys
     */
    public function testHmacToken(string $secret, string $algorithm): void
    {
        $token = $this->tokenFactory->create($this->payload, $secret);
        $this->tokenValidator->validate($token, $secret);

        $this->assertPayload($this->payload, $token);
        $this->assertHeader('typ', 'JWT', $token);
        $this->assertHeader('alg', $algorithm, $token);
    }

    /**
     * Проверяет JWT с подписью EC
     *
     * @param string $privateKey
     * @param string $publicKey
     *
     * @dataProvider provideEcKeys
     */
    public function testEcToken(string $privateKey, string $publicKey): void
    {
        $token = $this->tokenFactory->create($this->payload, $privateKey);
        $this->tokenValidator->validate($token, $publicKey);

        $this->assertPayload($this->payload, $token);
        $this->assertHeader('typ', 'JWT', $token);
        $this->assertHeader('alg', 'ES512', $token);
    }

    /**
     * Проверяет JWT с подписью Ed25519
     */
    public function testEd25519Token(): void
    {
        $privateKey = file_get_contents(__DIR__ . '/keys/ed25519/private.key');
        $publicKey  = file_get_contents(__DIR__ . '/keys/ed25519/public.key');

        $token = $this->tokenFactory->create($this->payload, $privateKey);
        $this->tokenValidator->validate($token, $publicKey);

        $this->assertPayload($this->payload, $token);
        $this->assertHeader('typ', 'JWT', $token);
        $this->assertHeader('alg', 'EdDSA', $token);
    }

    /**
     * Проверяет JWT с подписью RSA
     */
    public function testRsaToken(): void
    {
        $privateKey = file_get_contents(__DIR__ . '/keys/rsa/private.key');
        $publicKey  = file_get_contents(__DIR__ . '/keys/rsa/public.key');

        $token = $this->tokenFactory->create($this->payload, $privateKey);
        $this->tokenValidator->validate($token, $publicKey);

        $this->assertPayload($this->payload, $token);
        $this->assertHeader('typ', 'JWT', $token);
        $this->assertHeader('alg', 'PS512', $token);
    }

    /**
     * Проверяет создание JWT с паролем закрытого ключа
     */
    public function testTokenWithKeyPassword(): void
    {
        $privateKey = file_get_contents(__DIR__ . '/keys/pass/private.key');
        $publicKey  = file_get_contents(__DIR__ . '/keys/pass/public.key');

        $token = $this->tokenFactory->create($this->payload, $privateKey, 'test');
        $this->tokenValidator->validate($token, $publicKey);

        $this->assertPayload($this->payload, $token);
        $this->assertHeader('typ', 'JWT', $token);
        $this->assertHeader('alg', 'PS512', $token);
    }

    /**
     * Проверяет создание JWT с неподдерживаемым ключом
     *
     * @param string $key
     * @param string $algorithm
     *
     * @dataProvider provideUnsupportedKeys
     */
    public function testTokenWithUnsupportedKey(string $key, string $algorithm): void
    {
        $token = $this->tokenFactory->create($this->payload, $key);
        $this->tokenValidator->validate($token, $key);

        $this->assertPayload($this->payload, $token);
        $this->assertHeader('typ', 'JWT', $token);
        $this->assertHeader('alg', $algorithm, $token);
    }

    /**
     * Проверяет валидацию JWT, выпущенного в будущем
     */
    public function testValidationWithTokenFromFuture(): void
    {
        $token = $this->tokenFactory->create(['iat' => $this->day('tomorrow')]);

        $this->expectException(ValidatorException::class);
        $this->expectExceptionMessage('The JWT is issued in the future.');

        $this->tokenValidator->validate($token);
    }

    /**
     * Проверяет валидацию JWT, выпущенного для будущего использования
     */
    public function testValidationWithTokenForFuture(): void
    {
        $token = $this->tokenFactory->create(['nbf' => $this->day('tomorrow')]);

        $this->expectException(ValidatorException::class);
        $this->expectExceptionMessage('The JWT can not be used yet.');

        $this->tokenValidator->validate($token);
    }

    /**
     * Проверяет валидацию просроченного JWT
     */
    public function testValidationWithExpiredToken(): void
    {
        $token = $this->tokenFactory->create(['exp' => $this->day('-1 second')]);

        $this->expectException(ValidatorException::class);
        $this->expectExceptionMessage('The token expired.');

        $this->tokenValidator->validate($token);
    }

    /**
     * Проверяет валидацию некорректного JWT
     */
    public function testValidationWithInvalidToken(): void
    {
        $token = 'invalidToken';

        $this->expectException(ValidatorException::class);
        $this->expectExceptionMessage('Invalid JWT received');

        $this->tokenValidator->validate($token);
    }

    /**
     * Проверяет валидацию JWT с пустым составом ключа
     */
    public function testValidationWithEmptyPayload(): void
    {
        $token = $this->token([]);

        $this->expectException(ValidatorException::class);
        $this->expectExceptionMessage('Invalid JWT received');

        $this->tokenValidator->validate($token);
    }

    /**
     * Проверяет валидацию JWT без подписи
     */
    public function testValidationWithEmptySignature(): void
    {
        $token = substr($this->token(), 0, -1);

        $this->expectException(ValidatorException::class);
        $this->expectExceptionMessage('Invalid JWT received');

        $this->tokenValidator->validate($token);
    }

    /**
     * Проверяет валидацию JWT с некорректной подписью
     */
    public function testValidationWithInvalidSignature(): void
    {
        $token = $this->token() . 'invalidSignature';

        $this->expectException(ValidatorException::class);
        $this->expectExceptionMessage('JWT signature verification failed');

        $this->tokenValidator->validate($token);
    }

    /**
     * Проверяет валидацию JWT с некорректной подписью
     */
    public function testValidationWithInvalidPublicKey(): void
    {
        $privateKey = file_get_contents(__DIR__ . '/keys/rsa/private.key');
        $publicKey  = file_get_contents(__DIR__ . '/keys/ed25519/public.key');

        $token = $this->tokenFactory->create($this->payload, $privateKey);

        $this->expectException(ValidatorException::class);
        $this->expectExceptionMessage('JWT signature verification failed');

        $this->tokenValidator->validate($token, $publicKey);
    }

    /**
     * Возвращает ключи HMAC
     *
     * @return array
     *
     * @throws Throwable
     */
    public function provideHmacKeys(): array
    {
        $secrets = [
            31 => 'none',
            32 => 'HS256',
            47 => 'HS256',
            48 => 'HS384',
            63 => 'HS384',
            64 => 'HS512',
            65 => 'HS512',
        ];

        return array_map(
            fn ($bytes, $algorithm) => [
                random_bytes($bytes),
                $algorithm,
            ],
            array_keys($secrets),
            $secrets
        );
    }

    /**
     * Возвращает ключи EC
     *
     * @return array
     */
    public function provideEcKeys(): array
    {
        $keys = [
            'p256',
            'p384',
            'p521',
        ];

        return array_map(
            fn ($key) => [
                file_get_contents(sprintf(__DIR__ . '/keys/%s/private.key', $key)),
                file_get_contents(sprintf(__DIR__ . '/keys/%s/public.key', $key)),
            ],
            $keys
        );
    }

    /**
     * Возвращает неподдерживаемые ключи
     *
     * @return array
     */
    public function provideUnsupportedKeys(): array
    {
        return [
            [
                file_get_contents(__DIR__ . '/keys/x25519.key'),
                'HS512',
            ],
            [
                file_get_contents(__DIR__ . '/keys/empty.key'),
                'none',
            ],
            [
                'file://' . __DIR__ . '/keys/x25519.key',
                'HS512',
            ],
            [
                'file://' . __DIR__ . '/keys/empty.key',
                'HS256',
            ],
            [
                'file://invalid/path/to/key',
                'none',
            ],
            [
                __DIR__ . '/keys/x25519.key',
                'HS512',
            ],
            [
                __DIR__ . '/keys/empty.key',
                'HS256',
            ],
            [
                '/invalid/path/to/key',
                'none',
            ],
        ];
    }

    /**
     * Проверяет состав ключа
     *
     * @param array  $payload
     * @param string $token
     */
    private function assertPayload(array $payload, string $token): void
    {
        foreach ($payload as $claim => $value) {
            $this->assertClaim($claim, $value, $token);
        }
    }

    /**
     * Проверяет значение ключа
     *
     * @param string $claim
     * @param mixed  $value
     * @param string $token
     */
    private function assertClaim(string $claim, $value, string $token): void
    {
        $claims = json_decode(base64_decode(explode('.', $token)[1]), true);
        $this->assertSame($value, $claims[$claim]);
    }

    /**
     * Проверяет заголовок ключа
     *
     * @param string $header
     * @param string $value
     * @param string $token
     */
    private function assertHeader(string $header, string $value, string $token): void
    {
        $headers = json_decode(base64_decode(explode('.', $token)[0]), true);
        $this->assertSame($value, $headers[$header]);
    }

    /**
     * Возвращает заданный день
     *
     * @param string $modify
     *
     * @return int
     */
    private function day(string $modify): int
    {
        return Carbon::instance($this->now)->modify($modify)->getTimestamp();
    }

    /**
     * Создает JWT
     *
     * @param array|null $payload
     *
     * @return string
     */
    private function token(array $payload = null): string
    {
        if ($payload === null) {
            $payload = $this->payload;
        }

        return implode('.', [
            Base64Url::encode(json_encode([
                'typ' => 'JWT',
                'alg' => 'none',
            ])),
            Base64Url::encode(json_encode($payload)),
            '',
        ]);
    }
}

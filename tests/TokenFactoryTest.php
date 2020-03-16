<?php

declare(strict_types=1);

namespace Free2er\Jwt;

use Base64Url\Base64Url;
use Carbon\Carbon;
use Jose\Component\Core\Util\JsonConverter;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * Тест фабрики JWT
 */
class TokenFactoryTest extends TestCase
{
    /**
     * Текущее время
     *
     * @var int
     */
    private int $now = 1584390537;

    /**
     * Состав JWT
     *
     * @var array
     */
    private array $payload = [
        'aud'    => 'application',
        'sub'    => 'user',
        'iat'    => 1584390537,
        'nbf'    => 1584390537,
        'exp'    => 1584390538,
        'extra'  => ['test'],
    ];

    /**
     * Фабрика JWT
     *
     * @var TokenFactory|null
     */
    private ?TokenFactory $factory;

    /**
     * Инициализирует окружение перез запуском теста
     */
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::createFromTimestamp($this->now));
        $this->factory = new TokenFactory();
    }

    /**
     * Очищает окружение после завершения теста
     */
    protected function tearDown(): void
    {
        parent::tearDown();

        Carbon::setTestNow(null);
        $this->factory = null;
    }

    /**
     * Проверяет состав ключа
     */
    public function testPayload(): void
    {
        $this->assertEquals($this->payload, $this->fetchTokenPayload());
    }

    /**
     * Проверяет приложение по умолчанию
     */
    public function testDefaultAudience(): void
    {
        unset($this->payload['aud']);
        $this->assertEmpty($this->fetchTokenPayload()['aud']);
    }

    /**
     * Проверяет пользователя по умолчанию
     */
    public function testDefaultSubject(): void
    {
        unset($this->payload['sub']);
        $this->assertEmpty($this->fetchTokenPayload()['sub']);
    }

    /**
     * Проверяет дату создания ключа по умолчанию
     */
    public function testDefaultIssuedAt(): void
    {
        unset($this->payload['iat']);
        $this->assertEquals($this->now, $this->fetchTokenPayload()['iat']);
    }

    /**
     * Проверяет дату начала срока действия ключа по умолчанию
     */
    public function testDefaultNotBefore(): void
    {
        unset($this->payload['nbf']);
        $this->assertEquals($this->now, $this->fetchTokenPayload()['nbf']);
    }

    /**
     * Проверяет дату окончания срока действия ключа по умолчанию
     */
    public function testDefaultExpirationTime(): void
    {
        unset($this->payload['exp']);
        $this->assertEquals($this->now + 3600, $this->fetchTokenPayload()['exp']);
    }

    /**
     * Проверяет дополнительные сведения по умолчанию
     */
    public function testDefaultExtra(): void
    {
        unset($this->payload['extra']);
        $this->assertEquals($this->payload, $this->fetchTokenPayload());
    }

    /**
     * Проверяет подписание ключом RSA
     *
     * @throws Throwable
     */
    public function testRsaKeySigning(): void
    {
        $headers = $this->fetchTokenHeaders(__DIR__ . '/keys/rsa/private.key');
        $this->assertEquals('JWT', $headers['typ']);
        $this->assertEquals('PS512', $headers['alg']);

        $signature = $this->fetchTokenSignature(__DIR__ . '/keys/rsa/private.key');
        $this->assertNotEmpty($signature);
    }

    /**
     * Проверяет подписание ключом EC
     *
     * @throws Throwable
     */
    public function testEcKeySigning(): void
    {
        $keys = [
            'p256',
            'p384',
            'p521',
        ];

        foreach ($keys as $key) {
            $headers = $this->fetchTokenHeaders(__DIR__ . '/keys/' . $key . '/private.key');
            $this->assertEquals('JWT', $headers['typ']);
            $this->assertEquals('ES512', $headers['alg']);

            $signature = $this->fetchTokenSignature(__DIR__ . '/keys/' . $key . '/private.key');
            $this->assertNotEmpty($signature);
        }
    }

    /**
     * Проверяет подписание ключом Ed25519
     *
     * @throws Throwable
     */
    public function testEddsaKeySigning(): void
    {
        $headers = $this->fetchTokenHeaders(__DIR__ . '/keys/ed25519/private.key');
        $this->assertEquals('JWT', $headers['typ']);
        $this->assertEquals('EdDSA', $headers['alg']);

        $signature = $this->fetchTokenSignature(__DIR__ . '/keys/ed25519/private.key');
        $this->assertNotEmpty($signature);
    }

    /**
     * Проверяет подписание ключом HMAC
     *
     * @throws Throwable
     */
    public function testHmacKeySigning(): void
    {
        $headers = $this->fetchTokenHeaders(random_bytes(32));
        $this->assertEquals('JWT', $headers['typ']);
        $this->assertEquals('HS256', $headers['alg']);

        $headers = $this->fetchTokenHeaders(random_bytes(48));
        $this->assertEquals('JWT', $headers['typ']);
        $this->assertEquals('HS384', $headers['alg']);

        $headers = $this->fetchTokenHeaders(random_bytes(64));
        $this->assertEquals('JWT', $headers['typ']);
        $this->assertEquals('HS512', $headers['alg']);

        $signature = $this->fetchTokenSignature(random_bytes(32));
        $this->assertNotEmpty($signature);

        $signature = $this->fetchTokenSignature(random_bytes(48));
        $this->assertNotEmpty($signature);

        $signature = $this->fetchTokenSignature(random_bytes(64));
        $this->assertNotEmpty($signature);
    }

    /**
     * Проверяет подписание ключом None
     */
    public function testNoneKeySigning(): void
    {
        $headers = $this->fetchTokenHeaders(null);
        $this->assertEquals('JWT', $headers['typ']);
        $this->assertEquals('none', $headers['alg']);

        $signature = $this->fetchTokenSignature(null);
        $this->assertEmpty($signature);
    }

    /**
     * Создает JWT и возвращает его заголовки
     *
     * @param string|null $key
     *
     * @return array
     */
    private function fetchTokenHeaders(?string $key): array
    {
        $token = $this->factory->create($this->payload, $key);

        $payload = explode('.', $token)[0];
        $payload = Base64Url::decode($payload);
        $payload = JsonConverter::decode($payload);

        return $payload;
    }

    /**
     * Создает JWT и возвращает его состав
     *
     * @return array
     */
    private function fetchTokenPayload(): array
    {
        $token = $this->factory->create($this->payload);

        $payload = explode('.', $token)[1];
        $payload = Base64Url::decode($payload);
        $payload = JsonConverter::decode($payload);

        return $payload;
    }

    /**
     * Создает JWT и возвращает его подпись
     *
     * @param string|null $key
     *
     * @return string
     */
    private function fetchTokenSignature(?string $key): string
    {
        return explode('.', $this->factory->create($this->payload, $key))[2];
    }
}

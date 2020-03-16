<?php

declare(strict_types=1);

namespace Free2er\Jwt;

use PHPUnit\Framework\TestCase;

/**
 * Тест фабрики JWK
 */
class KeyFactoryTest extends TestCase
{
    /**
     * Фабрика JWK
     *
     * @var KeyFactory|null
     */
    private ?KeyFactory $factory;

    /**
     * Инициализирует окружение перез запуском теста
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->factory = new KeyFactory();
    }

    /**
     * Очищает окружение после завершения теста
     */
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->factory = null;
    }

    /**
     * Проверяет создание ключа с префиксом файла
     */
    public function testKeyWithFilePrefix(): void
    {
        $key = $this->factory->create('file://' . __DIR__ . '/keys/rsa/private.key');
        $this->assertEquals('RSA', $key->get('kty'));
    }

    /**
     * Проверяет создание ключа с паролем
     */
    public function testKeyWithPassword(): void
    {
        $key = $this->factory->create(__DIR__ . '/keys/pass/private.key', 'test');

        $this->assertEquals('RSA', $key->get('kty'));
        $this->assertEquals('PS512', $key->get('alg'));
        $this->assertTrue($key->has('n'));
        $this->assertTrue($key->has('e'));
        $this->assertTrue($key->has('d'));
        $this->assertTrue($key->has('p'));
        $this->assertTrue($key->has('q'));
        $this->assertTrue($key->has('dp'));
        $this->assertTrue($key->has('dq'));
        $this->assertTrue($key->has('qi'));

        $key = $this->factory->create(__DIR__ . '/keys/pass/public.key');

        $this->assertEquals('RSA', $key->get('kty'));
        $this->assertEquals('PS512', $key->get('alg'));
        $this->assertTrue($key->has('n'));
        $this->assertTrue($key->has('e'));
        $this->assertFalse($key->has('d'));
        $this->assertFalse($key->has('p'));
        $this->assertFalse($key->has('q'));
        $this->assertFalse($key->has('dp'));
        $this->assertFalse($key->has('dq'));
        $this->assertFalse($key->has('qi'));
    }

    /**
     * Проверяет создание ключей RSA
     */
    public function testRsaKey(): void
    {
        $key = $this->factory->create(__DIR__ . '/keys/rsa/private.key');

        $this->assertEquals('RSA', $key->get('kty'));
        $this->assertEquals('PS512', $key->get('alg'));
        $this->assertTrue($key->has('n'));
        $this->assertTrue($key->has('e'));
        $this->assertTrue($key->has('d'));
        $this->assertTrue($key->has('p'));
        $this->assertTrue($key->has('q'));
        $this->assertTrue($key->has('dp'));
        $this->assertTrue($key->has('dq'));
        $this->assertTrue($key->has('qi'));

        $key = $this->factory->create(__DIR__ . '/keys/rsa/public.key');

        $this->assertEquals('RSA', $key->get('kty'));
        $this->assertEquals('PS512', $key->get('alg'));
        $this->assertTrue($key->has('n'));
        $this->assertTrue($key->has('e'));
        $this->assertFalse($key->has('d'));
        $this->assertFalse($key->has('p'));
        $this->assertFalse($key->has('q'));
        $this->assertFalse($key->has('dp'));
        $this->assertFalse($key->has('dq'));
        $this->assertFalse($key->has('qi'));
    }

    /**
     * Проверяет создание ключей EC
     */
    public function testEcKey(): void
    {
        $keys = [
            'p256' => 'P-256',
            'p384' => 'P-384',
            'p521' => 'P-521',
        ];

        foreach ($keys as $type => $curve) {
            $key = $this->factory->create(__DIR__ . '/keys/' . $type . '/private.key');

            $this->assertEquals('EC', $key->get('kty'));
            $this->assertEquals('ES512', $key->get('alg'));
            $this->assertEquals($curve, $key->get('crv'));
            $this->assertTrue($key->has('x'));
            $this->assertTrue($key->has('y'));
            $this->assertTrue($key->has('d'));

            $key = $this->factory->create(__DIR__ . '/keys/' . $type . '/public.key');

            $this->assertEquals('EC', $key->get('kty'));
            $this->assertEquals('ES512', $key->get('alg'));
            $this->assertEquals($curve, $key->get('crv'));
            $this->assertTrue($key->has('x'));
            $this->assertTrue($key->has('y'));
            $this->assertFalse($key->has('d'));
        }
    }

    /**
     * Проверяет создание ключей Ed25519
     */
    public function testEd25519Key(): void
    {
        $key = $this->factory->create(__DIR__ . '/keys/ed25519/private.key');

        $this->assertEquals('OKP', $key->get('kty'));
        $this->assertEquals('EdDSA', $key->get('alg'));
        $this->assertEquals('Ed25519', $key->get('crv'));
        $this->assertTrue($key->has('x'));
        $this->assertTrue($key->has('d'));

        $key = $this->factory->create(__DIR__ . '/keys/ed25519/public.key');

        $this->assertEquals('OKP', $key->get('kty'));
        $this->assertEquals('EdDSA', $key->get('alg'));
        $this->assertEquals('Ed25519', $key->get('crv'));
        $this->assertTrue($key->has('x'));
        $this->assertFalse($key->has('d'));
    }

    /**
     * Проверяет создание ключа из файла X25519
     */
    public function testCreateFromX25519File(): void
    {
        $key = $this->factory->create(__DIR__ . '/keys/x25519.key');
        $this->assertEquals('oct', $key->get('kty'));
    }

    /**
     * Проверяет создание ключа из пустого файла
     */
    public function testCreateFromEmptyFile(): void
    {
        $key = $this->factory->create(__DIR__ . '/keys/empty.key');
        $this->assertEquals('oct', $key->get('kty'));
    }

    /**
     * Проверяет создание ключа из некорректного файла
     */
    public function testCreateFromInvalidFile(): void
    {
        $key = $this->factory->create('file:///invalid/file.key');
        $this->assertEquals('oct', $key->get('kty'));
    }

    /**
     * Проверяет создание ключей HMAC
     */
    public function testHmacKey(): void
    {
        $secret = '123456789012345678901234';

        $key = $this->factory->create($secret);
        $this->assertEquals('oct', $key->get('kty'));
        $this->assertEquals('HS256', $key->get('alg'));
        $this->assertTrue($key->has('k'));

        $key = $this->factory->create($secret . $secret);
        $this->assertEquals('HS384', $key->get('alg'));

        $key = $this->factory->create($secret . $secret . $secret);
        $this->assertEquals('HS512', $key->get('alg'));
    }

    /**
     * Проверяет создание ключей None
     */
    public function testNoneKey(): void
    {
        $key = $this->factory->create();

        $this->assertEquals('none', $key->get('kty'));
        $this->assertEquals('none', $key->get('alg'));
    }

    /**
     * Проверяет допустимые алгоритмы шифрования
     */
    public function testAlgorithms(): void
    {
        $algorithms = KeyFactory::algorithms()->list();

        $this->assertContains('none', $algorithms);
        $this->assertContains('HS256', $algorithms);
        $this->assertContains('HS384', $algorithms);
        $this->assertContains('HS512', $algorithms);
        $this->assertContains('PS512', $algorithms);
        $this->assertContains('ES512', $algorithms);
        $this->assertContains('EdDSA', $algorithms);
    }
}

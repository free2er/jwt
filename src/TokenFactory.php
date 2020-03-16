<?php

declare(strict_types=1);

namespace Free2er\Jwt;

use Carbon\Carbon;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;

/**
 * Фабрика JWT
 */
class TokenFactory
{
    /**
     * Фабрика JWK
     *
     * @var KeyFactory
     */
    private KeyFactory $keyFactory;

    /**
     * Сериализатор JWT
     *
     * @var JWSSerializer
     */
    private JWSSerializer $serializer;

    /**
     * Строитель JWT
     *
     * @var JWSBuilder
     */
    private JWSBuilder $builder;

    /**
     * Срок действия JWT
     *
     * @var int
     */
    private int $expirationTime;

    /**
     * Конструктор
     *
     * @param KeyFactory|null    $keyFactory
     * @param JWSSerializer|null $serializer
     * @param JWSBuilder|null    $builder
     * @param int|null           $expirationTime
     */
    public function __construct(
        KeyFactory $keyFactory = null,
        JWSSerializer $serializer = null,
        JWSBuilder $builder = null,
        int $expirationTime = null
    ) {
        $this->keyFactory     = $keyFactory ?: new KeyFactory();
        $this->serializer     = $serializer ?: new CompactSerializer();
        $this->builder        = $builder ?: new JWSBuilder(KeyFactory::algorithms());
        $this->expirationTime = $expirationTime ?: 3600;
    }

    /**
     * Создает JWT
     *
     * @param array       $payload
     * @param string|null $key
     * @param string|null $password
     *
     * @return string
     */
    public function create(array $payload, string $key = null, string $password = null): string
    {
        $key = $this->keyFactory->create($key, $password);
        $now = Carbon::now()->getTimestamp();

        $payload = array_merge(
            [
                'aud' => '',
                'sub' => '',
                'iat' => $now,
                'nbf' => $now,
                'exp' => $now + $this->expirationTime,
            ],
            $payload
        );

        $headers = [
            'typ' => 'JWT',
            'alg' => $key->get('alg')
        ];

        $token = $this->builder
            ->create()
            ->withPayload(JsonConverter::encode($payload))
            ->addSignature($key, $headers)
            ->build();

        return $this->serializer->serialize($token);
    }
}

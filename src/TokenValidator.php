<?php

declare(strict_types=1);

namespace Free2er\Jwt;

use Free2er\Jwt\Exception\ValidatorException;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;
use Throwable;

/**
 * Валидатор JWT
 */
class TokenValidator
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
     * Валидатор подписи JWT
     *
     * @var JWSVerifier
     */
    private JWSVerifier $verifier;

    /**
     * Валидатор состава JWT
     *
     * @var ClaimCheckerManager
     */
    private ClaimCheckerManager $payloadChecker;

    /**
     * Возвращает валидаторы состава JWT
     *
     * @return ClaimCheckerManager
     */
    private static function checkers(): ClaimCheckerManager
    {
        return new ClaimCheckerManager([
            new IssuedAtChecker(),
            new NotBeforeChecker(),
            new ExpirationTimeChecker(),
        ]);
    }

    /**
     * Конструктор
     *
     * @param KeyFactory|null          $keyFactory
     * @param JWSSerializer|null       $serializer
     * @param JWSVerifier|null         $verifier
     * @param ClaimCheckerManager|null $payloadChecker
     */
    public function __construct(
        KeyFactory $keyFactory = null,
        JWSSerializer $serializer = null,
        JWSVerifier $verifier = null,
        ClaimCheckerManager $payloadChecker = null
    ) {
        $this->keyFactory     = $keyFactory ?: new KeyFactory();
        $this->serializer     = $serializer ?: new CompactSerializer();
        $this->verifier       = $verifier ?: new JWSVerifier(KeyFactory::algorithms());
        $this->payloadChecker = $payloadChecker ?: static::checkers();
    }

    /**
     * Проверяет JWT
     *
     * @param string      $token
     * @param string|null $key
     * @param string|null $password
     *
     * @throws ValidatorException
     */
    public function validate(string $token, string $key = null, string $password = null): void
    {
        try {
            $token = $this->serializer->unserialize($token);
        } catch (Throwable $exception) {
            throw ValidatorException::parse($exception);
        }

        try {
            $payload = JsonConverter::decode($token->getPayload());
        } catch (Throwable $exception) {
            throw ValidatorException::parse($exception);
        }

        if (!$payload || !is_array($payload)) {
            throw ValidatorException::parse();
        }

        try {
            $this->payloadChecker->check($payload, array_keys($this->payloadChecker->getCheckers()));
        } catch (Throwable $exception) {
            throw ValidatorException::payload($exception);
        }

        $key = $this->keyFactory->create($key, $password);

        try {
            $verified = $this->verifier->verifyWithKey($token, $key, 0);
        } catch (Throwable $exception) {
            throw ValidatorException::signature($exception);
        }

        if (!$verified) {
            throw ValidatorException::signature();
        }
    }
}

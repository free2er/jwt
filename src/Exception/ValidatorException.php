<?php

declare(strict_types=1);

namespace Free2er\Jwt\Exception;

use RuntimeException;
use Throwable;

/**
 * Ошибка проверки JWT
 */
class ValidatorException extends RuntimeException
{
    /**
     * Ошибка разбора JWT
     *
     * @param Throwable|null $exception
     *
     * @return static
     */
    public static function parse(Throwable $exception = null): self
    {
        return new static('Invalid JWT received', $exception);
    }

    /**
     * Ошибка проверки состава JWT
     *
     * @param Throwable $exception
     *
     * @return static
     */
    public static function payload(Throwable $exception): self
    {
        return new static($exception->getMessage(), $exception);
    }

    /**
     * Ошибка проверки подписи JWT
     *
     * @param Throwable|null $exception
     *
     * @return static
     */
    public static function signature(Throwable $exception = null): self
    {
        return new static('JWT signature verification failed', $exception);
    }

    /**
     * Конструктор
     *
     * @param string         $message
     * @param Throwable|null $previous
     */
    public function __construct(string $message, Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}

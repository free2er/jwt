<?php

declare(strict_types=1);

namespace Free2er\Jwt\Exception;

use RuntimeException;
use Throwable;

/**
 * Ошибка создания JWK
 */
class KeyException extends RuntimeException
{
    /**
     * Оборачивает ошибку
     *
     * @param Throwable $exception
     *
     * @return static
     */
    public static function wrap(Throwable $exception): self
    {
        return new static($exception->getMessage(), $exception->getCode(), $exception);
    }
}

<?php

namespace XD\PasswordlessLogin\Support;

/**
 * Immutable value object describing what to deliver to a member: either a numeric
 * CODE or a login LINK (URL). Passed to an OtpDeliveryChannel so channels can
 * render the right message without the service knowing channel details.
 */
final class LoginMessage
{
    public const TYPE_CODE = 'code';
    public const TYPE_LINK = 'link';

    public function __construct(
        public readonly string $type,
        public readonly ?string $code = null,
        public readonly ?string $url = null,
        public readonly int $ttlMinutes = 10,
    ) {
    }

    public static function code(string $code, int $ttlMinutes): self
    {
        return new self(self::TYPE_CODE, code: $code, ttlMinutes: $ttlMinutes);
    }

    public static function link(string $url, int $ttlMinutes): self
    {
        return new self(self::TYPE_LINK, url: $url, ttlMinutes: $ttlMinutes);
    }

    public function isCode(): bool
    {
        return $this->type === self::TYPE_CODE;
    }

    public function isLink(): bool
    {
        return $this->type === self::TYPE_LINK;
    }
}

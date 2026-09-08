<?php

namespace XD\PasswordlessLogin\Model;

use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;

/**
 * A single-use, hashed, expiring login secret — either a short numeric CODE the
 * member types, or the VERIFIER of a login LINK.
 *
 * The plaintext secret is NEVER stored: only password_hash($secret) in
 * SecretHash. Codes are looked up by (Email + session binding); links use the
 * selector/verifier split so the URL token is never stored or table-scanned:
 * Selector (indexed, plaintext) finds the row, the verifier is hash-verified.
 *
 * @property string $Type       'code' | 'link'
 * @property string $Email
 * @property string $Selector   link only: URL lookup key
 * @property string $SecretHash password_hash of the code, or of the link verifier
 * @property string $ExpiresAt
 * @property int    $Attempts
 * @property string $ConsumedAt
 * @property string $IP
 * @property string $SessionToken code only: binds the code to the requesting session
 * @method Member Member()
 */
class LoginToken extends DataObject
{
    public const TYPE_CODE = 'code';
    public const TYPE_LINK = 'link';

    private static $table_name = 'PasswordlessLogin_LoginToken';

    private static $db = [
        'Type' => "Enum('code,link','code')",
        'Email' => 'Varchar(255)',
        'Selector' => 'Varchar(32)',
        'SecretHash' => 'Varchar(255)',
        'ExpiresAt' => 'Datetime',
        'Attempts' => 'Int',
        'ConsumedAt' => 'Datetime',
        'IP' => 'Varchar(45)',
        'SessionToken' => 'Varchar(64)',
    ];

    private static $has_one = [
        'Member' => Member::class,
    ];

    private static $indexes = [
        'Email' => true,
        'Selector' => true,
        'ConsumedAt' => true,
    ];

    private static $default_sort = 'ID DESC';

    public function isExpired(): bool
    {
        return strtotime((string) $this->ExpiresAt) < DBDatetime::now()->getTimestamp();
    }

    public function isConsumed(): bool
    {
        return (bool) $this->ConsumedAt;
    }

    public function isUsable(): bool
    {
        return $this->isInDB() && !$this->isConsumed() && !$this->isExpired();
    }

    public function canView($member = null)
    {
        return false;
    }

    public function canEdit($member = null)
    {
        return false;
    }

    public function canCreate($member = null, $context = [])
    {
        return false;
    }

    public function canDelete($member = null)
    {
        return false;
    }
}

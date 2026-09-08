<?php

namespace XD\PasswordlessLogin\Resolver;

use SilverStripe\Security\Member;
use XD\PasswordlessLogin\Contract\OtpMemberResolver;

/**
 * Default resolver: log in an existing Member matched on Email. No account is
 * created. Projects that need just-in-time creation or extra rules provide their
 * own implementation via the Injector.
 */
class ExistingMemberResolver implements OtpMemberResolver
{
    public function memberForEmail(string $email): ?Member
    {
        $email = trim($email);
        if ($email === '') {
            return null;
        }
        // Case-insensitive: the service lowercases input, but stored addresses may
        // be mixed-case and the column collation is not guaranteed to fold case.
        return Member::get()->filter('Email:nocase', $email)->first();
    }
}

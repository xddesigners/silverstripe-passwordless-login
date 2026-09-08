<?php

namespace XD\PasswordlessLogin\Contract;

use SilverStripe\Security\Member;

/**
 * Resolves a submitted e-mail address to the Member that should be logged in —
 * the project's "who is allowed in" rule. Return null to deny (the caller
 * always shows the same neutral message, so returning null never reveals
 * whether the address exists).
 *
 * The default implementation matches an existing Member by Email. Projects
 * override this (via Injector) to add rules and/or just-in-time account
 * creation — e.g. "only active members, create the account on first login".
 */
interface OtpMemberResolver
{
    public function memberForEmail(string $email): ?Member;
}

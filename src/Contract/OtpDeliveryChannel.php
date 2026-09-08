<?php

namespace XD\PasswordlessLogin\Contract;

use SilverStripe\Security\Member;
use XD\PasswordlessLogin\Support\LoginMessage;

/**
 * Delivers a login message (a code or a link) to a member. The default channel
 * is e-mail; an SMS channel can be added by implementing this interface and
 * pointing the Injector binding at it — no change to the core flow.
 *
 * Implementations resolve their own destination from the member (e-mail address,
 * mobile number, …) and MUST NOT log or expose the code/link.
 */
interface OtpDeliveryChannel
{
    /** Whether this channel can reach the member (has the needed contact detail). */
    public function canDeliver(Member $member): bool;

    /** Deliver the message. Throws on failure. Never store/log the secret. */
    public function deliver(Member $member, LoginMessage $message): void;
}

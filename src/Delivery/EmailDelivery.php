<?php

namespace XD\PasswordlessLogin\Delivery;

use SilverStripe\Control\Email\Email;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Security\Member;
use XD\PasswordlessLogin\Contract\OtpDeliveryChannel;
use XD\PasswordlessLogin\Support\LoginMessage;

/**
 * Default delivery channel: e-mails the code or link to the member. Templates
 * (templates/XD/PasswordlessLogin/Email/LoginCode.ss and LoginLink.ss) are
 * overridable per project.
 */
class EmailDelivery implements OtpDeliveryChannel
{
    use Configurable;

    private static ?string $from_email = null;

    public function canDeliver(Member $member): bool
    {
        return (bool) $member->Email;
    }

    public function deliver(Member $member, LoginMessage $message): void
    {
        $email = Email::create();
        if ($from = $this->config()->get('from_email')) {
            $email->setFrom($from);
        }
        $email->setTo($member->Email);

        if ($message->isLink()) {
            $email->setSubject(_t(self::class . '.SubjectLink', 'Your login link'));
            $email->setHTMLTemplate('XD/PasswordlessLogin/Email/LoginLink');
            $email->setData([
                'Member' => $member,
                'Url' => $message->url,
                'TtlMinutes' => $message->ttlMinutes,
            ]);
        } else {
            $email->setSubject(_t(self::class . '.SubjectCode', 'Your login code'));
            $email->setHTMLTemplate('XD/PasswordlessLogin/Email/LoginCode');
            $email->setData([
                'Member' => $member,
                'Code' => $message->code,
                'TtlMinutes' => $message->ttlMinutes,
            ]);
        }

        $email->send();
    }
}

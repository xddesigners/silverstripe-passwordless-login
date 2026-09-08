<?php

namespace XD\PasswordlessLogin\Authenticator;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Validation\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;

/**
 * Primary, passwordless authenticator. It only advertises the LOGIN service (no
 * password/change/reset/CMS services), so registering it alongside the default
 * MemberAuthenticator leaves CMS/admin password login untouched. The actual
 * authentication happens in the login handler via OtpService — there is no
 * credential authenticate() path.
 */
class PasswordlessAuthenticator implements Authenticator
{
    use Injectable;

    public function supportedServices()
    {
        return Authenticator::LOGIN;
    }

    public function getLoginHandler($link)
    {
        return PasswordlessLoginHandler::create($link, $this);
    }

    public function getLogOutHandler($link)
    {
        return null;
    }

    public function getChangePasswordHandler($link)
    {
        return null;
    }

    public function getLostPasswordHandler($link)
    {
        return null;
    }

    public function authenticate(array $data, HTTPRequest $request, ?ValidationResult &$result = null)
    {
        // Passwordless has no credential-based authenticate() path; the handler
        // logs the member in directly once a code/link is verified.
        return null;
    }

    public function checkPassword(Member $member, $password, ?ValidationResult &$result = null)
    {
        $result = $result ?: ValidationResult::create();
        $result->addError(_t(__CLASS__ . '.NoPassword', 'This account has no password; sign in with a code or link.'));
        return $result;
    }
}

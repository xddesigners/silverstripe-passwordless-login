<?php

namespace XD\PasswordlessLogin\Security;

use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Security;
use XD\PasswordlessLogin\Authenticator\PasswordlessAuthenticator;

/**
 * Scopes which login authenticators are offered by context, so front-end members
 * see ONLY passwordless and admins see ONLY the password login — without
 * touching either authenticator's registration.
 *
 * Opt-in: a project activates it by binding Security to this class in the
 * Injector. Detection is by the login's BackURL/target: admin-bound → password,
 * everything else → passwordless. If filtering would leave no way in, the full
 * set is returned (fail-open so nobody is ever locked out).
 */
class ScopedSecurity extends Security
{
    private static bool $scope_by_admin_context = true;

    public function getApplicableAuthenticators($service = Authenticator::LOGIN)
    {
        $all = parent::getApplicableAuthenticators($service);

        if ($service !== Authenticator::LOGIN || !static::config()->get('scope_by_admin_context')) {
            return $all;
        }

        $request = $this->getRequest();
        if (!$request) {
            return $all;
        }

        $wantPasswordless = !$this->isAdminContext($request);
        $filtered = [];
        foreach ($all as $name => $authenticator) {
            $isPasswordless = $authenticator instanceof PasswordlessAuthenticator;
            if ($wantPasswordless === $isPasswordless) {
                $filtered[$name] = $authenticator;
            }
        }

        return $filtered ?: $all;
    }

    private function isAdminContext(HTTPRequest $request): bool
    {
        $target = (string) ($request->getVar('BackURL') ?: $request->getSession()->get('BackURL'));
        if ($target === '') {
            $target = (string) $request->getURL();
        }
        return $this->isAdminUrl($target);
    }

    private function isAdminUrl(string $url): bool
    {
        $url = ltrim(Director::makeRelative($url), '/');
        $adminBase = 'admin';
        if (class_exists(\SilverStripe\Admin\AdminRootController::class)) {
            $configured = ltrim((string) \SilverStripe\Admin\AdminRootController::admin_url(), '/');
            if ($configured !== '') {
                $adminBase = rtrim($configured, '/');
            }
        }
        return $url === $adminBase || str_starts_with($url, $adminBase . '/');
    }
}

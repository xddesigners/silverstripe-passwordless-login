<?php

namespace XD\PasswordlessLogin\Tests;

use SilverStripe\Dev\FunctionalTest;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;
use XD\PasswordlessLogin\Model\LoginToken;

/**
 * The login link, from landing to logged in. The landing must not redirect: a browser that came from another site
 * (webmail) would leave the SameSite=Strict session cookie out of the redirected request.
 */
class LinkLoginTest extends FunctionalTest
{
    protected $usesDatabase = true;

    protected $autoFollowRedirection = false;

    private const VERIFIER = 'a-verifier-only-for-this-test';

    protected function setUp(): void
    {
        parent::setUp();
        $this->logOut();
    }

    private function link(int $expiresIn = 600): string
    {
        $member = Member::create(['FirstName' => 'Lin', 'Email' => uniqid() . '@example.test']);
        $member->write();
        $token = LoginToken::create();
        $token->Type = LoginToken::TYPE_LINK;
        $token->Email = $member->Email;
        $token->MemberID = $member->ID;
        $token->Selector = bin2hex(random_bytes(9));
        $token->SecretHash = password_hash(self::VERIFIER, PASSWORD_DEFAULT);
        $token->ExpiresAt = date('Y-m-d H:i:s', DBDatetime::now()->getTimestamp() + $expiresIn);
        $token->write();
        return 'Security/login/passwordless/link?token=' . $token->Selector . '.' . self::VERIFIER;
    }

    /** The URL the landing page moves on to (it must be a page, not a redirect). */
    private function landingTarget(string $link): string
    {
        $response = $this->get($link);
        $this->assertSame(200, $response->getStatusCode());
        $this->assertNull($response->getHeader('Location'));
        $this->assertSame('no-referrer', $response->getHeader('Referrer-Policy'));
        $body = (string) $response->getBody();
        $this->assertStringNotContainsString(self::VERIFIER, $body, 'the token does not appear in the page');
        $this->assertDoesNotMatchRegularExpression('/<(script|link|img|iframe)\b/i', $body, 'the page loads nothing');
        $this->assertSame(1, preg_match('/http-equiv="refresh" content="0; url=([^"]+)"/', $body, $match));
        return html_entity_decode($match[1]);
    }

    public function testLinkLogsInAfterConfirmation(): void
    {
        $link = $this->link();
        $target = $this->landingTarget($link);
        $this->assertStringEndsWith('/Security/login/passwordless/confirm', $target);
        $this->assertEmpty($this->session()->get('loggedInAs'), 'opening the link does not log in (mail scanners)');

        $this->assertStringContainsString('ConfirmForm', (string) $this->get($target)->getBody());
        $this->submitForm('Form_ConfirmForm', 'action_doConfirm');
        $this->assertSame((int) LoginToken::get()->first()->MemberID, (int) $this->session()->get('loggedInAs'));

        $this->assertStringEndsWith('/Security/login/passwordless', $this->landingTarget($link), 'single use');
    }

    public function testInvalidLinkGoesToTheLoginFormWithAMessage(): void
    {
        foreach ([$this->link(-60), 'Security/login/passwordless/link?token=no.good'] as $link) {
            $target = $this->landingTarget($link);
            $this->assertStringEndsWith('/Security/login/passwordless', $target);
            $message = _t('XD\PasswordlessLogin\Authenticator\PasswordlessLoginHandler.LinkInvalid', 'This login link is not valid or has expired.');
            $this->assertStringContainsString($message, (string) $this->get($target)->getBody());
        }
    }
}

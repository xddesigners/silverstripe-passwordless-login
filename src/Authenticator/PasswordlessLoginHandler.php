<?php

namespace XD\PasswordlessLogin\Authenticator;

use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Core\Convert;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\Form;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\HeaderField;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\OptionsetField;
use SilverStripe\Forms\Validation\RequiredFieldsValidator;
use SilverStripe\Forms\TextField;
use SilverStripe\Core\Validation\ValidationResult;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Security;
use SilverStripe\i18n\i18n;
use XD\PasswordlessLogin\Model\LoginToken;
use XD\PasswordlessLogin\Service\OtpService;
use XD\PasswordlessLogin\Support\LoginMessage;

/**
 * Two-step passwordless login handler, plus the login-link landing/confirm flow.
 *
 *  login()   step 1: e-mail + method → sends a code or a link
 *  verify()  step 2 (code): enter the code → logged in
 *  link()    link landing (GET): validates the token, then sends the visitor on to…
 *  confirm() …a POST confirm page (defeats e-mail link prefetch) → logged in
 *
 * All rendering goes through Security's login page; transitions use redirects +
 * session messages so nothing reveals whether an address exists. Only the link
 * landing answers with a page of its own, see continueTo().
 */
class PasswordlessLoginHandler extends RequestHandler
{
    private const S_EMAIL = 'PasswordlessLogin.Email';
    private const S_BACKURL = 'PasswordlessLogin.BackURL';
    private const S_LINK_ID = 'PasswordlessLogin.PendingLinkTokenID';
    private const S_NOTICE = 'PasswordlessLogin.VerifyNotice';

    private static $url_handlers = [
        'verify' => 'verify',
        'link' => 'linklogin',
        'confirm' => 'confirm',
        '' => 'login',
    ];

    private static $allowed_actions = [
        'login',
        'verify',
        'linklogin',
        'confirm',
        'RequestForm',
        'VerifyForm',
        'ConfirmForm',
    ];

    protected $link;

    protected $authenticator;

    public function __construct($link, PasswordlessAuthenticator $authenticator)
    {
        $this->link = $link;
        $this->authenticator = $authenticator;
        parent::__construct();
    }

    public function Link($action = null)
    {
        $link = Controller::join_links($this->link, $action);
        $this->extend('updateLink', $link, $action);
        return $link;
    }

    private function service(): OtpService
    {
        return OtpService::singleton();
    }

    // ------------------------------------------------------- external entry

    /**
     * Start the code step for an e-mail address from elsewhere, e.g. right after
     * a registration form created the account. Requests a code exactly like the
     * request form does (resolver, rate limits and session binding all apply),
     * remembers where to go after login, and returns the URL of the code step to
     * redirect the visitor to.
     *
     * @param string|null $backURL local URL to return to after login
     * @param string|null $notice  optional message shown above the code field
     */
    public static function startCodeLogin(
        HTTPRequest $request,
        string $email,
        ?string $backURL = null,
        ?string $notice = null
    ): string {
        OtpService::singleton()->requestCode($email, $request);

        $session = $request->getSession();
        $session->set(self::S_EMAIL, $email);
        if ($backURL && Director::is_site_url($backURL)) {
            $session->set(self::S_BACKURL, $backURL);
        }
        if ($notice) {
            $session->set(self::S_NOTICE, ['text' => $notice, 'type' => 'good']);
        } else {
            $session->clear(self::S_NOTICE);
        }

        return static::verifyLink();
    }

    /**
     * URL of the code step: <login url>/<name of the passwordless authenticator>/verify.
     */
    public static function verifyLink(): string
    {
        $name = 'passwordless';
        foreach (Security::singleton()->getAuthenticators() as $authName => $authenticator) {
            if ($authenticator instanceof PasswordlessAuthenticator) {
                $name = $authName;
                break;
            }
        }
        return Controller::join_links(Security::login_url(), $name, 'verify');
    }

    // ---------------------------------------------------------------- step 1

    public function login()
    {
        // Remember where to return to after login.
        if ($back = $this->getBackURL()) {
            $this->getRequest()->getSession()->set(self::S_BACKURL, $back);
        }
        return ['Form' => $this->RequestForm()];
    }

    public function RequestForm(): Form
    {
        $fields = FieldList::create(
            LiteralField::create(
                'RequestIntro',
                '<p class="passwordless-login__intro">'
                . _t(__CLASS__ . '.RequestIntro', 'Enter your e-mail address and we will send you a login code.')
                . '</p>'
            ),
            $emailField = TextField::create('Email', _t(__CLASS__ . '.Email', 'E-mail address'))
        );
        $emailField->setAttribute('type', 'email')->setAttribute('autocomplete', 'email');

        $methods = $this->service()->enabledMethods();
        if (count($methods) > 1) {
            $source = [];
            if (in_array('code', $methods, true)) {
                $source['code'] = _t(__CLASS__ . '.MethodCode', 'E-mail me a code');
            }
            if (in_array('link', $methods, true)) {
                $source['link'] = _t(__CLASS__ . '.MethodLink', 'E-mail me a login link');
            }
            $fields->push(
                OptionsetField::create('Method', _t(__CLASS__ . '.Method', 'How would you like to sign in?'), $source, 'code')
            );
        }

        $actions = FieldList::create(
            FormAction::create('doRequest', _t(__CLASS__ . '.Send', 'Continue'))
        );

        $form = Form::create($this, 'RequestForm', $fields, $actions, RequiredFieldsValidator::create('Email'));
        $this->extend('updateRequestForm', $form);
        return $form;
    }

    public function doRequest($data, Form $form)
    {
        $request = $this->getRequest();
        // Starting a fresh request; clear any standing verify-step notice.
        $this->clearVerifyNotice();
        $email = (string) ($data['Email'] ?? '');
        $methods = $this->service()->enabledMethods();
        $method = (string) ($data['Method'] ?? ($methods[0] ?? 'code'));

        if ($method === LoginMessage::TYPE_LINK && $this->service()->isMethodEnabled(LoginMessage::TYPE_LINK)) {
            $this->service()->requestLink($email, $request);
            $this->message(
                _t(__CLASS__ . '.LinkSent', 'If your address is known, a login link has been sent. Check your e-mail.'),
                ValidationResult::TYPE_GOOD
            );
            return $this->redirect($this->Link());
        }

        // Code (default).
        $this->service()->requestCode($email, $request);
        $request->getSession()->set(self::S_EMAIL, $email);
        return $this->redirect($this->Link('verify'));
    }

    // ---------------------------------------------------------------- step 2

    public function verify()
    {
        $request = $this->getRequest();
        if (!$request->getSession()->get(self::S_EMAIL)) {
            return $this->redirect($this->Link());
        }

        $form = $this->VerifyForm();
        $this->applyVerifyNotice($form);
        return ['Form' => $form];
    }

    public function VerifyForm(): Form
    {
        $fields = FieldList::create(
            HeaderField::create('VerifyHeading', _t(__CLASS__ . '.VerifyHeading', 'Enter your login code'), 2),
            LiteralField::create(
                'VerifyIntro',
                '<p class="passwordless-login__intro">'
                . _t(
                    __CLASS__ . '.VerifyIntro',
                    'If your address is known to us, we have e-mailed you a login code. Enter it below to sign in.'
                )
                . '</p>'
            ),
            $code = TextField::create('Code', _t(__CLASS__ . '.Code', 'Login code'))
        );
        $code->setAttribute('autocomplete', 'one-time-code')
            ->setAttribute('inputmode', 'numeric');

        $actions = FieldList::create(
            FormAction::create('doVerify', _t(__CLASS__ . '.SignIn', 'Sign in')),
            // Exempt from validation so it works without a code entered.
            // formnovalidate also skips any client-side (HTML5/Bootstrap)
            // validation on the empty code field when this button is used.
            // Rendered as a subtle text/link-style button (see extra classes).
            FormAction::create('doResend', _t(__CLASS__ . '.Resend', 'Send a new code'))
                ->setValidationExempt(true)
                ->setAttribute('formnovalidate', 'formnovalidate')
                ->addExtraClass('btn btn-link passwordless-login__resend')
        );

        $form = Form::create($this, 'VerifyForm', $fields, $actions, RequiredFieldsValidator::create('Code'));

        // Let the host project augment the form (e.g. add an organisation-specific
        // "no e-mail? contact us" notice, extra fields, icons).
        $this->extend('updateVerifyForm', $form);

        return $form;
    }

    public function doResend($data, Form $form)
    {
        $request = $this->getRequest();
        $email = (string) $request->getSession()->get(self::S_EMAIL);
        if (!$email) {
            return $this->redirect($this->Link());
        }

        // Rate limiting / cooldown inside the service means a too-soon resend is
        // silently ignored (the previous code stays valid); the response is the
        // same either way so nothing is revealed. The notice drives the
        // confirmation message on the next verify render.
        $this->service()->requestCode($email, $request);
        $this->setVerifyNotice(
            _t(__CLASS__ . '.ResendSent', 'If your address is known, a new code has been sent. Check your e-mail.'),
            ValidationResult::TYPE_GOOD
        );
        return $this->redirect($this->Link('verify'));
    }

    public function doVerify($data, Form $form)
    {
        $request = $this->getRequest();
        // The visitor is acting on the code now; clear any standing notice.
        $this->clearVerifyNotice();
        $email = (string) $request->getSession()->get(self::S_EMAIL);
        $code = (string) ($data['Code'] ?? '');

        $member = $email ? $this->service()->verifyCode($email, $code, $request) : null;
        if (!$member) {
            $this->setVerifyNotice(
                _t(__CLASS__ . '.BadCode', 'That code is not valid or has expired. Please try again.'),
                ValidationResult::TYPE_ERROR
            );
            return $this->redirect($this->Link('verify'));
        }

        $request->getSession()->clear(self::S_EMAIL);
        $this->performLogin($member);
        return $this->redirectAfterLogin();
    }

    // -------------------------------------------------- verify-step notices

    /**
     * Store a notice to show once on the next verify render. Rendered inline
     * (below the heading) rather than as a form-level message, which the theme
     * renders above the page title.
     */
    private function setVerifyNotice(string $text, string $type): void
    {
        $this->getRequest()->getSession()->set(self::S_NOTICE, [
            'text' => $text,
            'type' => $type === ValidationResult::TYPE_GOOD ? 'good' : 'error',
        ]);
    }

    private function clearVerifyNotice(): void
    {
        $this->getRequest()->getSession()->clear(self::S_NOTICE);
    }

    /**
     * Render any standing notice as an inline alert after the intro. Not cleared
     * on render — a stray duplicate GET (e.g. the dev debugbar re-running the
     * request) would otherwise consume it before the visible page shows it. It
     * is cleared when the visitor next acts (submits a code) or restarts.
     */
    private function applyVerifyNotice(Form $form): void
    {
        $notice = $this->getRequest()->getSession()->get(self::S_NOTICE);
        if (!is_array($notice) || empty($notice['text'])) {
            return;
        }
        $type = ($notice['type'] ?? 'error') === 'good' ? 'good' : 'error';
        $form->Fields()->insertAfter('VerifyIntro', LiteralField::create(
            'VerifyNotice',
            '<div class="alert alert-' . $type . ' passwordless-login__notice" role="status">'
            . Convert::raw2xml((string) $notice['text'])
            . '</div>'
        ));
    }

    // ------------------------------------------------------------ link flow

    public function linklogin()
    {
        $request = $this->getRequest();
        $token = (string) $request->getVar('token');
        $row = $this->service()->findValidLinkToken($token);

        if (!$row) {
            $this->message(
                _t(__CLASS__ . '.LinkInvalid', 'This login link is not valid or has expired.'),
                ValidationResult::TYPE_ERROR
            );
            return $this->continueTo($this->Link());
        }

        if ($back = $this->getBackURL()) {
            $request->getSession()->set(self::S_BACKURL, $back);
        }
        // Store the reference and go on to a clean URL (strips the token).
        $request->getSession()->set(self::S_LINK_ID, (int) $row->ID);
        return $this->continueTo($this->Link('confirm'));
    }

    /**
     * Send the visitor on from the link landing with a page of our own instead of
     * a redirect. A link clicked in webmail is a cross-site navigation: browsers
     * hold back SameSite=Strict cookies (the Silverstripe 6 default) for that
     * request and for every redirect it leads to, so the session started here
     * would be missing on the next page. A navigation that our own page starts is
     * same-site, and does get the cookie.
     *
     * The page is bare on purpose: its URL still holds the token, so it loads
     * nothing and sends no referrer.
     */
    private function continueTo(string $link): HTTPResponse
    {
        $url = Convert::raw2att(Director::absoluteURL($link));
        $lang = Convert::raw2att(str_replace('_', '-', i18n::get_locale()));
        $label = Convert::raw2xml(_t(__CLASS__ . '.LinkContinue', 'Continue'));

        $html = <<<HTML
            <!DOCTYPE html>
            <html lang="{$lang}">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <meta name="robots" content="noindex">
                <meta name="referrer" content="no-referrer">
                <meta http-equiv="refresh" content="0; url={$url}">
                <title>{$label}</title>
            </head>
            <body><p><a href="{$url}">{$label}</a></p></body>
            </html>
            HTML;

        return HTTPResponse::create($html)
            ->addHeader('Content-Type', 'text/html; charset=utf-8')
            ->addHeader('Referrer-Policy', 'no-referrer');
    }

    public function confirm()
    {
        $row = $this->pendingLinkToken();
        if (!$row) {
            $this->message(
                _t(__CLASS__ . '.LinkInvalid', 'This login link is not valid or has expired.'),
                ValidationResult::TYPE_ERROR
            );
            return $this->redirect($this->Link());
        }
        return ['Form' => $this->ConfirmForm()];
    }

    public function ConfirmForm(): Form
    {
        $fields = FieldList::create(
            HiddenField::create('Confirm', null, '1')
        );
        $actions = FieldList::create(
            FormAction::create('doConfirm', _t(__CLASS__ . '.ConfirmSignIn', 'Confirm sign in'))
        );
        $form = Form::create($this, 'ConfirmForm', $fields, $actions);
        $this->extend('updateConfirmForm', $form);
        return $form;
    }

    public function doConfirm($data, Form $form)
    {
        $request = $this->getRequest();
        $row = $this->pendingLinkToken();
        $member = $row ? $row->Member() : null;

        if (!$row || !$member || !$member->exists()) {
            $this->message(
                _t(__CLASS__ . '.LinkInvalid', 'This login link is not valid or has expired.'),
                ValidationResult::TYPE_ERROR
            );
            return $this->redirect($this->Link());
        }

        $this->service()->consume($row);
        $request->getSession()->clear(self::S_LINK_ID);
        $this->performLogin($member);
        return $this->redirectAfterLogin();
    }

    private function pendingLinkToken(): ?LoginToken
    {
        $id = (int) $this->getRequest()->getSession()->get(self::S_LINK_ID);
        if ($id <= 0) {
            return null;
        }
        $row = LoginToken::get()->byID($id);
        return ($row && $row->Type === LoginToken::TYPE_LINK && $row->isUsable()) ? $row : null;
    }

    // ----------------------------------------------------------------- util

    private function performLogin($member): void
    {
        Injector::inst()->get(IdentityStore::class)->logIn($member, false, $this->getRequest());
    }

    private function redirectAfterLogin()
    {
        $session = $this->getRequest()->getSession();
        $back = (string) $session->get(self::S_BACKURL);
        $session->clear(self::S_BACKURL);

        // Only ever redirect to a local URL (anti open-redirect).
        if ($back && Director::is_site_url($back)) {
            return $this->redirect($back);
        }
        $dest = Security::config()->get('default_login_dest') ?: '/';
        return $this->redirect($dest);
    }

    private function message(string $text, string $type): void
    {
        // Attach to the login form (shown once on the next login-page render, then
        // cleared). Security's GLOBAL session message can linger across pages —
        // it would otherwise still appear after logout.
        $this->RequestForm()->sessionMessage($text, $type);
    }
}

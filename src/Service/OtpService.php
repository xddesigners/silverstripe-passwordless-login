<?php

namespace XD\PasswordlessLogin\Service;

use Psr\Log\LoggerInterface;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Cache\CacheFactory;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;
use Throwable;
use XD\PasswordlessLogin\Contract\OtpDeliveryChannel;
use XD\PasswordlessLogin\Contract\OtpMemberResolver;
use XD\PasswordlessLogin\Model\LoginToken;
use XD\PasswordlessLogin\Support\LoginMessage;

/**
 * Issues and verifies single-use passwordless login secrets: short numeric CODES
 * (member types them) and login LINKS (member clicks; verified on a confirm page).
 *
 * Security properties (both methods):
 *  - CSPRNG secrets; stored only as password_hash(); constant-time verification.
 *  - Single active token per e-mail: a new request invalidates older ones.
 *  - Short TTL, per-e-mail cooldown, per-IP rate limiting.
 *  - Enumeration-hardened: request*() returns nothing and burns a bcrypt on the
 *    deny path, so an unknown address is not distinguishable by result or timing
 *    (e-mail send latency is the residual signal; rate limiting bounds it).
 *  - The plaintext secret never touches storage, and (for links) never the DB —
 *    the URL uses a selector/verifier split.
 *
 * Codes additionally bind to the requesting browser session and cap attempts.
 * Links use a high-entropy verifier (brute-force infeasible) and are meant to be
 * confirmed via a POST on a landing page (defeats e-mail link prefetching) — the
 * controller consumes the token there.
 */
class OtpService
{
    use Injectable;
    use Configurable;

    private static bool $enable_code = true;
    private static bool $enable_link = true;
    private static int $code_length = 6;
    private static int $ttl_seconds = 600;
    private static int $link_ttl_seconds = 900;
    private static int $max_attempts = 5;
    private static int $request_cooldown_seconds = 30;
    private static int $ip_max_requests = 10;
    private static int $ip_window_seconds = 3600;
    private static bool $bind_to_session = true;
    private static string $link_path = 'passwordless-login/link';

    private const SESSION_KEY = 'PasswordlessLogin.SessionToken';

    public function isMethodEnabled(string $method): bool
    {
        if ($method === LoginMessage::TYPE_CODE) {
            return (bool) $this->config()->get('enable_code');
        }
        if ($method === LoginMessage::TYPE_LINK) {
            return (bool) $this->config()->get('enable_link');
        }
        return false;
    }

    /** The enabled methods, in display order. */
    public function enabledMethods(): array
    {
        $methods = [];
        if ($this->isMethodEnabled(LoginMessage::TYPE_CODE)) {
            $methods[] = LoginMessage::TYPE_CODE;
        }
        if ($this->isMethodEnabled(LoginMessage::TYPE_LINK)) {
            $methods[] = LoginMessage::TYPE_LINK;
        }
        return $methods;
    }

    /**
     * Request a numeric CODE. Always safe to call; reveals nothing about whether
     * the address exists.
     */
    public function requestCode(string $email, HTTPRequest $request): void
    {
        if (!$this->isMethodEnabled(LoginMessage::TYPE_CODE)) {
            return;
        }
        [$member, $memberEmail] = $this->beginRequest($email, $request);
        if (!$member) {
            return;
        }

        $this->invalidateActiveFor($memberEmail, LoginToken::TYPE_CODE);

        $code = $this->generateCode();
        $sessionToken = bin2hex(random_bytes(32));

        $token = LoginToken::create();
        $token->Type = LoginToken::TYPE_CODE;
        $token->Email = $memberEmail;
        $token->MemberID = $member->ID;
        $token->SecretHash = password_hash($code, PASSWORD_DEFAULT);
        $token->ExpiresAt = $this->expiryFrom((int) $this->config()->get('ttl_seconds'));
        $token->Attempts = 0;
        $token->IP = $this->ip($request);
        $token->SessionToken = $this->config()->get('bind_to_session') ? $sessionToken : null;
        $token->write();

        if ($this->config()->get('bind_to_session')) {
            $request->getSession()->set(self::SESSION_KEY, $sessionToken);
        }

        $ttlMinutes = (int) ceil(((int) $this->config()->get('ttl_seconds')) / 60);
        $this->deliver($member, LoginMessage::code($code, $ttlMinutes), $request);
    }

    /**
     * Request a login LINK. The URL carries a selector.verifier token; only the
     * verifier's hash is stored. Not session-bound (links open cross-device).
     */
    public function requestLink(string $email, HTTPRequest $request): void
    {
        if (!$this->isMethodEnabled(LoginMessage::TYPE_LINK)) {
            return;
        }
        [$member, $memberEmail] = $this->beginRequest($email, $request);
        if (!$member) {
            return;
        }

        $this->invalidateActiveFor($memberEmail, LoginToken::TYPE_LINK);

        $selector = bin2hex(random_bytes(9));
        $verifier = bin2hex(random_bytes(32));

        $token = LoginToken::create();
        $token->Type = LoginToken::TYPE_LINK;
        $token->Email = $memberEmail;
        $token->MemberID = $member->ID;
        $token->Selector = $selector;
        $token->SecretHash = password_hash($verifier, PASSWORD_DEFAULT);
        $token->ExpiresAt = $this->expiryFrom((int) $this->config()->get('link_ttl_seconds'));
        $token->Attempts = 0;
        $token->IP = $this->ip($request);
        $token->write();

        $path = ltrim((string) $this->config()->get('link_path'), '/');
        $url = Director::absoluteURL($path) . '?token=' . urlencode($selector . '.' . $verifier);
        $ttlMinutes = (int) ceil(((int) $this->config()->get('link_ttl_seconds')) / 60);
        $this->deliver($member, LoginMessage::link($url, $ttlMinutes), $request);
    }

    /**
     * Verify a submitted CODE for an e-mail. Returns the Member on success, null
     * otherwise. The caller logs the member in.
     */
    public function verifyCode(string $email, string $code, HTTPRequest $request): ?Member
    {
        $email = $this->normaliseEmail($email);
        $code = trim($code);
        if ($email === '' || $code === '') {
            return null;
        }

        $token = LoginToken::get()
            ->filter(['Type' => LoginToken::TYPE_CODE, 'Email' => $email, 'ConsumedAt' => null])
            ->sort('ID DESC')
            ->first();
        if (!$token || $token->isExpired()) {
            return null;
        }

        if ($this->config()->get('bind_to_session')) {
            $sessionToken = (string) $request->getSession()->get(self::SESSION_KEY);
            if ($sessionToken === '' || !hash_equals((string) $token->SessionToken, $sessionToken)) {
                return null;
            }
        }

        if (!password_verify($code, (string) $token->SecretHash)) {
            $token->Attempts = (int) $token->Attempts + 1;
            $token->write();
            if ((int) $token->Attempts >= (int) $this->config()->get('max_attempts')) {
                $this->consume($token);
            }
            $this->logger()?->notice('passwordless: bad code', ['member' => $token->MemberID, 'ip' => $this->ip($request)]);
            return null;
        }

        $member = $token->Member();
        $this->consume($token);
        if ($this->config()->get('bind_to_session')) {
            $request->getSession()->clear(self::SESSION_KEY);
        }

        // The member may have been deleted after the code was issued; a has_one
        // returns an empty (ID 0) Member, not null — reject that.
        if (!$member || !$member->exists()) {
            $this->logger()?->warning('passwordless: token member missing', ['member' => $token->MemberID]);
            return null;
        }

        $this->logger()?->info('passwordless: code login ok', ['member' => $member->ID, 'ip' => $this->ip($request)]);

        return $member;
    }

    /**
     * Validate a LINK token (selector.verifier) WITHOUT consuming it — used to
     * render the confirm page. Returns the token, or null if invalid/expired.
     */
    public function findValidLinkToken(string $token): ?LoginToken
    {
        $token = trim($token);
        if (!str_contains($token, '.')) {
            return null;
        }
        [$selector, $verifier] = explode('.', $token, 2);
        if ($selector === '' || $verifier === '') {
            return null;
        }

        $row = LoginToken::get()
            ->filter(['Type' => LoginToken::TYPE_LINK, 'Selector' => $selector, 'ConsumedAt' => null])
            ->first();
        if (!$row || !$row->isUsable()) {
            return null;
        }
        if (!password_verify($verifier, (string) $row->SecretHash)) {
            return null;
        }
        return $row;
    }

    /** Mark a token used (call once the member is actually logged in). */
    public function consume(LoginToken $token): void
    {
        $token->ConsumedAt = DBDatetime::now()->getValue();
        $token->write();
    }

    /** Delete consumed/expired tokens. Call from a scheduled cleanup task. */
    public function purgeStale(): int
    {
        $now = DBDatetime::now()->getValue();
        $stale = LoginToken::get()->filterAny([
            'ConsumedAt:not' => null,
            'ExpiresAt:LessThan' => $now,
        ]);
        $count = 0;
        foreach ($stale as $token) {
            $token->delete();
            $count++;
        }
        return $count;
    }

    /**
     * Shared front half of a request: rate-limit, resolve the member, cooldown
     * and channel checks. Returns [Member, normalisedEmail] or [null, ''].
     */
    private function beginRequest(string $email, HTTPRequest $request): array
    {
        $email = $this->normaliseEmail($email);
        if ($email === '' || !$this->passesIpRateLimit($request)) {
            return [null, ''];
        }

        $member = Injector::inst()->get(OtpMemberResolver::class)->memberForEmail($email);
        if (!$member || !$member->Email) {
            // Equalise the dominant (bcrypt) cost so an unknown address does not
            // return measurably faster than a known one (enumeration hardening).
            $this->burnHash();
            return [null, ''];
        }
        $memberEmail = $this->normaliseEmail($member->Email);

        if (!$this->passesEmailCooldown($memberEmail)) {
            return [null, ''];
        }
        if (!Injector::inst()->get(OtpDeliveryChannel::class)->canDeliver($member)) {
            return [null, ''];
        }
        return [$member, $memberEmail];
    }

    private function deliver(Member $member, LoginMessage $message, HTTPRequest $request): void
    {
        try {
            Injector::inst()->get(OtpDeliveryChannel::class)->deliver($member, $message);
            $this->logger()?->info('passwordless: message sent', [
                'member' => $member->ID,
                'type' => $message->type,
                'ip' => $this->ip($request),
            ]);
        } catch (Throwable $e) {
            $this->logger()?->error('passwordless: delivery failed', ['error' => $e->getMessage()]);
        }
    }

    private function generateCode(): string
    {
        $length = max(4, (int) $this->config()->get('code_length'));
        $max = (10 ** $length) - 1;
        return str_pad((string) random_int(0, $max), $length, '0', STR_PAD_LEFT);
    }

    private function invalidateActiveFor(string $email, string $type): void
    {
        $active = LoginToken::get()->filter(['Email' => $email, 'Type' => $type, 'ConsumedAt' => null]);
        foreach ($active as $token) {
            $this->consume($token);
        }
    }

    /** Burn ~one bcrypt's worth of time to level the enumeration timing oracle. */
    private function burnHash(): void
    {
        password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT);
    }

    private function passesEmailCooldown(string $email): bool
    {
        $cooldown = (int) $this->config()->get('request_cooldown_seconds');
        if ($cooldown <= 0) {
            return true;
        }
        $recent = LoginToken::get()->filter('Email', $email)->sort('ID DESC')->first();
        if (!$recent) {
            return true;
        }
        return strtotime((string) $recent->Created) <= (DBDatetime::now()->getTimestamp() - $cooldown);
    }

    private function passesIpRateLimit(HTTPRequest $request): bool
    {
        $max = (int) $this->config()->get('ip_max_requests');
        if ($max <= 0) {
            return true;
        }
        $window = max(1, (int) $this->config()->get('ip_window_seconds'));
        $cache = Injector::inst()->get(CacheFactory::class)->create('passwordlessLogin');
        // Fixed window bucket: the key rolls over per window, so set() never
        // extends an existing window's expiry. (PSR-16 has no atomic increment,
        // so under heavy parallelism this is best-effort defence-in-depth.)
        $bucket = intdiv(DBDatetime::now()->getTimestamp(), $window);
        $key = 'ip_' . hash('sha256', $this->ip($request)) . '_' . $bucket;
        $count = (int) ($cache->get($key) ?? 0);
        if ($count >= $max) {
            return false;
        }
        $cache->set($key, $count + 1, $window);
        return true;
    }

    private function expiryFrom(int $ttlSeconds): string
    {
        return date('Y-m-d H:i:s', DBDatetime::now()->getTimestamp() + $ttlSeconds);
    }

    private function ip(HTTPRequest $request): string
    {
        return substr((string) $request->getIP(), 0, 45);
    }

    private function normaliseEmail(string $email): string
    {
        return mb_strtolower(trim($email));
    }

    private function logger(): ?LoggerInterface
    {
        try {
            return Injector::inst()->get(LoggerInterface::class);
        } catch (Throwable $e) {
            return null;
        }
    }
}

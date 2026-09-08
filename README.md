# Passwordless Login for Silverstripe

Passwordless **primary** login for Silverstripe CMS: members sign in with a
single-use one-time code sent to their e-mail (or, via a pluggable channel, SMS).
No passwords.

> Not to be confused with `xddesigners/otp-authenticator`, which adds an OTP as a
> **second factor** on top of a password via `silverstripe/mfa`. This module
> **replaces** the password as the primary method.

## How it works

The member enters their e-mail and picks a method (both configurable):

- **Code** — a short numeric code is delivered; the member types it in. Bound to
  the requesting browser session.
- **Link** — a one-time login link is delivered; clicking it lands on a
  **confirm page** (a POST), which defeats e-mail link prefetchers/scanners that
  would otherwise trip an auto-login. The URL uses a selector/verifier token
  (high entropy, never stored in plaintext).

Either way, if the e-mail resolves to an allowed member, the account is logged in.

## Extension points

Two Injector-bound seams let a project adapt the module without touching its core:

- **`OtpMemberResolver`** — maps an e-mail to the `Member` to log in (deny with
  `null`). Default: match an existing `Member` by e-mail. Override to add rules
  and/or just-in-time account creation.

  ```php
  class MyResolver implements XD\PasswordlessLogin\Contract\OtpMemberResolver
  {
      public function memberForEmail(string $email): ?SilverStripe\Security\Member { /* … */ }
  }
  ```

- **`OtpDeliveryChannel`** — how the code reaches the member. Default:
  `EmailDelivery`. Implement this and repoint the binding to add SMS.

```yaml
SilverStripe\Core\Injector\Injector:
  XD\PasswordlessLogin\Contract\OtpMemberResolver:
    class: App\MyResolver
```

## Security

Designed against the OWASP Authentication guidance:

- Codes generated with a CSPRNG (`random_int`); **stored only as `password_hash()`**,
  never in plaintext. Verification is constant-time (`password_verify` / `hash_equals`).
- **Single use**: a new request invalidates prior codes; a code is burned once used.
- **Short TTL** (default 10 min) and **capped attempts** (default 5, then invalidated).
- **Rate limiting**: per-e-mail cooldown and per-IP request cap.
- **Enumeration-hardened**: neutral responses, per-IP/per-e-mail rate limiting,
  and constant-work hashing on the deny path so a request does not reveal — by
  result or by timing — whether an address is a member. (E-mail send latency is
  the residual signal; rate limiting bounds its exploitability.)
- **Session binding** (default on): a code only verifies in the browser session
  that requested it — an intercepted code is useless elsewhere.
- The plaintext code never appears in URLs, storage or logs. Audit events are
  logged without the code.
- Forms carry CSRF protection; the session is regenerated on login (anti-fixation).
- **Serve over HTTPS** with secure cookies (Silverstripe 6 defaults to this).

Configurable via `XD\PasswordlessLogin\Service\OtpService` (code length, TTL,
attempts, cooldown, IP window, session binding).

## Housekeeping

`OtpService::purgeStale()` deletes consumed/expired codes — call it from a
scheduled task.

## Licence

BSD-3-Clause.

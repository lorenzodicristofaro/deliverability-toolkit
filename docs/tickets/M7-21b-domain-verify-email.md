# M7-21b Domain ownership verification by email
Milestone: M7
Branch: feature/m7-21b-domain-verify-email
Files in scope: app/services/domain_verification.py (extend), app/services/domain_verification_email.py (new, may reuse the M7-16 mail sender), app/models/domain.py and a migration only if M7-21a lacks the columns (prefer reusing them; a separate table for email challenges is allowed), app/repositories/ (challenge storage, TenantContext-bound for owner actions), app/api/v1/domains.py or domain_verification.py (start-email endpoint), public confirmation route (new, unauthenticated, e.g. app/web/domain_verify_public.py plus router registry line), app/web/templates/domains/ (button, address picker, confirmation page), app/core/config.py (rate limit settings) and .env.example, docs/SETUP.md, tests/services/test_domain_verification_email.py, tests/api/test_domain_verification_email.py, locales/en.json, locales/it.json, ARCHITECTURE.md (section 5/7/9 notes, proposed by the coder, edited per CLAUDE.md)
Out of scope: inbound mail, a new SMTP client (use the M7-16 relay only), other verification methods, SPEC.md
Depends on: M7-21a, M7-16 (notification SMTP relay)
Parallel-safe: no (domain verification service, locales, router registry, config)
Model: opus (unauthenticated endpoint, token handling, tenant isolation, outbound mail to attacker-influenced addresses)
Maintainer decision 2026-11-17: email is the alternative verification method; DNS TXT (M7-21a) stays preferred.
Acceptance criteria:
- Owner/admin (domain.verify) choose one role address at the domain from a fixed list: admin@, administrator@, hostmaster@, postmaster@, webmaster@. The list is a project choice modelled on common CA practice; whether it matches any vendor or CA requirement is an `unverified` fact and the UI/docs must not present it as a standard requirement. No address outside the list is accepted (server-side, table-driven test with lookalikes, plus-addressing, case, whitespace, CR/LF, other domains, subdomains).
- A one-time token (>= 128-bit, `secrets`), hashed at rest, short bounded expiry (setting), single use, re-send invalidates the previous one. The mail contains a link (BASE_URL) and optionally a short code; the token is never logged.
- Rate limits as settings: sends per domain and per tenant per time window (bounded, defaults in docs/SETUP.md); exceeding gives 429 with an i18n message and no mail. Recipient is never an arbitrary user-supplied address, so the relay cannot be used for spam.
- Link confirmation requires no login and CSRF-safe design (GET shows a confirm page, POST confirms, or equivalent so mail scanners prefetching the link do not verify); it verifies only that exact domain/token pair, sets verified with method `email`, consumes the token, and reveals no tenant data (no tenant name, no other domains, same generic page for unknown, expired and used tokens). Constant-time hash comparison.
- A rename of the domain (M7-21a) invalidates pending email challenges.
- SMTP relay not configured -> start returns a clear error (`not_configured`), nothing is stored as pending. Send failures follow the M7-16 retryable/permanent mapping and never mark the domain verified.
- Email template i18n en + it, plain text plus simple HTML, all values escaped, header-injection safe (no CR/LF in headers, domain name validated before use).
- Tests with a fake mailer, no network: send ok, address not in list, rate limit per domain and per tenant, expired, reused, wrong token, token of another domain, prefetch (GET alone does not verify), unconfigured relay, permission/tenancy cases for the start endpoint (cross-tenant 404, analyst and client viewer denied, CSRF), public page leaks nothing.
- Audit entry if the mechanism exists, as in M7-21a.
Unverified external facts: the role-address list is a project choice; CA/Browser Forum or other vendor requirements were not checked and must not be claimed.
New i18n keys: DOMAIN_VERIFY_EMAIL_SUBJECT, DOMAIN_VERIFY_EMAIL_BODY (intro/link/footer), DOMAIN_VERIFY_EMAIL_SENT, DOMAIN_VERIFY_EMAIL_RATE_LIMITED, DOMAIN_VERIFY_EMAIL_NOT_CONFIGURED, DOMAIN_VERIFY_EMAIL_ADDRESS_INVALID, DOMAIN_VERIFY_CONFIRM_TITLE/BODY, DOMAIN_VERIFY_CONFIRM_DONE, DOMAIN_VERIFY_CONFIRM_INVALID (en + it); exact names finalised by the coder
Note from M7-21a (done, ea6d500): the method CHECK already allows 'email', so no table rebuild is needed. Reuse the outcomes in app/services/domain_verification.py and the conditional `mark_verified`; same permission `domain.verify`.
Status: todo

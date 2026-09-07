# django-authlib

Authentication utilities for Django: a minimal custom user app
(`little_auth`), OAuth2/OAuth1 login clients (Google, Microsoft, Facebook,
Twitter), magic-link ("passwordless") email login, an `admin_oauth` app for
SSO-gating the Django admin login page, and a small role-based permissions
backend (`authlib.roles` / `authlib.backends.PermissionsBackend`).

Published to PyPI as `django-authlib`. Repo: feincms/django-authlib.

## Dev workflow

- Run tests: `cd tests && python manage.py test` (uses `tests/testapp/settings.py`,
  sqlite in-memory DB, no external network calls — OAuth providers are mocked
  with `requests_mock`).
- Lint: `ruff check authlib/` (ruff config lives in `pyproject.toml`).
- Pre-commit hooks (ruff, ruff-format, django-upgrade, biome, etc.) run on
  commit; don't bypass them with `--no-verify`.
- Install for local dev: `pip install -e ".[tests]"`.
- Commit feature by feature: one self-contained change per commit,
  together with its tests and its documentation (`CHANGELOG.rst`, `README.rst`,
  this file). Don't lump unrelated changes together.
- Commit messages carry no attribution: no `Co-Authored-By` trailers, no
  "generated with" footers.

## Layout

- `authlib/base_user.py`, `authlib/little_auth/` — abstract `BaseUser` +
  concrete `little_auth.User` (email-as-username, obfuscated `__str__`/
  `get_full_name` via `_obfuscate()` in `little_auth/models.py`).
- `authlib/backends.py` — `EmailBackend` (auth by email, no password) and
  `PermissionsBackend` (delegates `has_perm` to a per-role callback via
  `RoleField._role_has_perm`, enumerates all permissions by testing every
  known `Permission` against that callback).
- `authlib/roles.py` — `RoleField` (a `CharField` with choices sourced from
  `settings.AUTHLIB_ROLES`) and `allow_deny_globs`, a ready-made callback for
  allow/deny fnmatch-style permission rules.
- `authlib/views.py` — generic `login`, `oauth2`, `email_registration`,
  `logout` views usable in any project's urlconf.
- `authlib/email.py` — magic-link signing (`django.core.signing.TimestampSigner`)
  and mail rendering (`render_to_mail`, subject = first non-empty line of the
  `.txt` template, body = the rest).
- `authlib/google.py`, `authlib/microsoft.py`, `authlib/facebook.py`,
  `authlib/twitter.py` — one OAuth client class per provider, each
  self-contained (no shared base class — small duplication like the base64
  padding helper across google.py/microsoft.py is the accepted style here,
  not an oversight).
- `authlib/admin_oauth/` — separate SSO flow for the Django admin login page,
  with regex-pattern-based email→admin-username mapping
  (`ADMIN_OAUTH_PATTERNS`) and optional auto-provisioning
  (`ADMIN_OAUTH_CREATE_USER_CALLBACK`).

## Known nuances / open items (as of 2026-09-07)

- **OAuth2 `state` (CSRF) is now validated** for Google/Microsoft/Facebook
  logins (Twitter/OAuth1 was already fine — it independently binds
  `oauth_token` to the Django session server-side). Previously each request
  instantiated a fresh `OAuth2Session`, so the `state` generated in
  `get_authentication_url()` was never persisted, and
  `requests_oauthlib`/`oauthlib` silently skip state validation when
  `state=None` (`if state and params.get('state') != state`) — meaning the
  OAuth2 callback had no CSRF protection at all (an attacker could complete
  their own OAuth dance and hand a victim's browser the resulting
  `code`/`state`, logging the victim into the attacker's linked account).
  Fixed by persisting `state` in `request.session` across the redirect and
  rejecting callbacks with no matching pending state (raises `ValueError`
  in `get_user_data()`, caught by the existing generic error handling in
  `views.oauth2` / `admin_oauth.views.admin_oauth`). This means the two
  legs of the OAuth2 dance (start redirect, then callback) must now happen
  within the same session — true for every real browser, but the test
  suite previously skipped the start leg in ~10 places and had to be
  updated to do the real round-trip (see `start_oauth()` /
  `_authorized_client()` helpers in `tests/testapp/test_authlib.py`).
  Caveat: the one-time-use part (`session.pop()`) only really holds with a
  server-side `SESSION_ENGINE` (db/cache/file). With `signed_cookies`
  sessions there's no server-side record to delete — popping just tells the
  client to move on via a new `Set-Cookie`, but an old copy of the cookie
  (leaked via XSS, a proxy log, browser history, etc.) still carries a
  live, unconsumed `state` and stays validly signed for up to
  `SESSION_COOKIE_AGE` (2 weeks by default). The core forgery protection
  (attacker can't predict/plant a `state` without ever having had a copy of
  a real cookie) is unaffected either way. Prefer a server-side session
  backend if the one-time-use property matters to you.
- **Magic links (`authlib/email.py`) are intentionally reusable until
  expiry**, not single-use — left that way on purpose, not just because it
  was already tested. `tests/testapp/test_registration.py::test_registration`
  explicitly re-clicks the same link multiple times (including from a fresh
  `Client()`, simulating another device/session) and expects it to keep
  working until the max_age (or until the user is deactivated).
  Considered making links single-use (cache-backed, consumed on first
  successful login), but corporate email gateways and antivirus products
  routinely GET-prefetch every link in an email before the recipient ever
  opens it ("link preflighting" / Safe Links-style scanning) — naive
  single-use would burn the link before the real user clicks it. The
  correct fix (validate on GET, only consume on a subsequent POST/click)
  would change the view's contract for every downstream project using
  `authlib.views.email_registration` or hand-rolling their own view around
  `authlib.email.decode()`, and since this library ships no default
  templates, it'd also require every consumer to add a new confirmation
  template. Decided to hold off rather than ship a partial/breaking fix;
  document the tradeoff (reusable-until-expiry, replayable if the link
  leaks within the expiry window) instead. If this gets revisited, the
  GET-validates/POST-consumes split is the right shape.
- `PermissionsBackend.get_user_permissions()` must never cache results when
  `obj is not None` — role callbacks can decide differently per object, so
  caching on the user instance without keying on `obj` leaks stale results
  across objects (fixed 2026-09-07; mirrors how Django's own `ModelBackend`
  bypasses its cache whenever `obj is not None`).
- `_all_perms()` in `backends.py` is a process-lifetime `functools.cache` of
  every `Permission` in the DB — fine in practice since permissions rarely
  change at runtime, but worth remembering if a long-running process needs
  newly-migrated permissions without a restart.

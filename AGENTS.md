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

- **OAuth2 `state` (CSRF) is currently not validated** for Google/Microsoft/
  Facebook logins (Twitter/OAuth1 is fine — it binds `oauth_token` to the
  Django session server-side). Root cause: each request instantiates a fresh
  `OAuth2Session`, so the `state` generated in `get_authentication_url()` is
  never persisted, and `requests_oauthlib`/`oauthlib` silently skip state
  validation when `state=None` (`if state and params.get('state') != state`).
  A real fix means persisting `state` in `request.session` across the
  redirect and rejecting callbacks with no matching pending state — but a
  lot of the existing OAuth tests call the callback URL directly without
  first hitting the "start" URL (no session state ever gets set), and the
  Microsoft unit tests build requests via bare `RequestFactory()` with no
  session middleware at all. Fixing this properly means updating those
  tests to do the real two-step redirect+callback dance. Not yet done —
  needs a decision on how much of the test suite to touch.
- **Magic links (`authlib/email.py`) are intentionally reusable until
  expiry**, not single-use. `tests/testapp/test_registration.py::test_registration`
  explicitly re-clicks the same link multiple times (including from a fresh
  `Client()`, simulating another device/session) and expects it to keep
  working until the max_age (or until the user is deactivated). Don't "fix"
  this into single-use without checking — it would break that test and may
  be a deliberate multi-device design choice, not an oversight.
- `PermissionsBackend.get_user_permissions()` must never cache results when
  `obj is not None` — role callbacks can decide differently per object, so
  caching on the user instance without keying on `obj` leaks stale results
  across objects (fixed 2026-09-07; mirrors how Django's own `ModelBackend`
  bypasses its cache whenever `obj is not None`).
- `_all_perms()` in `backends.py` is a process-lifetime `functools.cache` of
  every `Permission` in the DB — fine in practice since permissions rarely
  change at runtime, but worth remembering if a long-running process needs
  newly-migrated permissions without a restart.

==========
Change log
==========

Next version
============


0.18 (2026-07-02)
=================

- Added two missing methods to the ``PermissionsBackend`` so that the admin app
  list works correctly.
- Added verification of the ``next`` cookie value also when setting the cookie,
  not just when reading it.
- Added Python 3.13, Django 5.2a1.
- Added Microsoft OAuth as backend and ``admin_oauth`` option.


0.17 (2024-08-19)
=================

- Changed the roles implementation to allow using arbitrary names for the role
  field.
- Stopped crashing when encountering an unknown role -- doing nothing in
  ``has_perm`` is an acceptable fallback.
- Force account selection when failing to authenticate once in the Django admin
  using a Google account.
- Added support for Django 5.1.
- Exempted our login views from the ``LoginRequiredMiddleware``.
- Dropped Django 4.1 from the CI. 3.2 is still there.
- Changed the default ``authlib.little_auth`` admin to hide the user
  permissions field; permissions should preferrably be added via authlib roles,
  or less preferrably via group permissions.


0.16 (2023-09-17)
=================

- Fixed ``pyproject.toml`` so that data files are actually included.
- Dropped compatibility with Python 3.8.
- Added utilities for role-based permissions. The idea is to allow a less
  manual way to specify permissions for groups of users, e.g. content managers
  which should automatically have access to all models in a list of apps
  without having to manually update the list of permissions in the Django
  administration interface.


0.15 (2023-07-07)
=================

- Added Python 3.11.
- Switched to hatchling and ruff.
- Added the option to create admin users during admin OAuth if one doesn't
  exist already. The ``ADMIN_OAUTH_CREATE_USER_CALLBACK`` setting should be set
  to the Python path of a callable receiving the request and the email address;
  this callable can (but doesn't have to) create a new user for the email
  address if one doesn't exist already. The default is to not create any users.
  Adding ``ADMIN_OAUTH_CREATE_USER_CALLBACK =
  "authlib.admin_oauth.views.create_superuser"`` makes creation of new
  superuser accounts automatic.


`0.14`_ (2023-03-21)
====================

.. _0.14: https://github.com/matthiask/django-authlib/compare/0.13...0.14

- Added Django 4.1 and 4.2 to the CI matrix.
- Made the bundled OAuth2 views pass the exception message to
  ``messages.error`` to ease debugging a bit.
- Changed the confirmation code used by ``authlib.email`` to be base64 encoded.
  This avoids problems where some email clients would mangle the link because
  of the included email address. Older codes are still accepted for the moment.
- Added a note regarding ``OAUTHLIB_INSECURE_TRANSPORT`` to the README.


`0.13`_ (2022-02-28)
====================

.. _0.13: https://github.com/matthiask/django-authlib/compare/0.12...0.13

- Added a ``default_auto_field`` to the ``little_auth`` appconfig.


`0.12`_ (2022-01-04)
====================

.. _0.12: https://github.com/matthiask/django-authlib/compare/0.11...0.12

- Added pre-commit.
- Dropped Python < 3.8, Django < 3.2.
- Added docs for how to integrate the email registration functionality.


`0.11`_ (2021-11-22)
====================

- Switched to a declarative setup.
- Switched from Travis CI to GitHub actions.
- Added Python 3.10, Django 4.0 to the CI.
- Avoided the additional request to Google endpoints since the access token
  already contains identity information in the ``id_token`` field.


`0.10`_ (2020-10-04)
====================

- Modified ``authlib.admin_oauth`` to persist the users' email address
  and pass it to Google as a ``login_hint`` so that website managers do
  not have to repeatedly select the account over and over.
- Allowed specifying arbitrary query parameters for Google's
  authorization URL.
- Fixed an ``authlib.admin_oauth`` crash when fetching user data fails.
- Replaced ``ugettext*`` with ``gettext*``.
- Replaced ``url()`` with ``re_path()``.
- Fixed a crash when creating ``little_auth`` users with invalid email
  addresses.
- Stopped carrying over login hints from one user to the other in the
  Google OAuth client...
- **BACKWARDS INCOMPATIBLE** Dropped the request argument from
  ``authlib.email.get_confirmation_code``, it wasn't used, ever.


`0.9`_ (2019-02-09)
===================

- Dropped support for Python 2.
- Fixed a few problems around inactive users where authlib would either
  handle them incorrectly or reveal that inactive users exist.
- Added many unittests, raised the code coverage to 100% (except for the
  uncovered Facebook and Twitter OAuth clients). Switched to mocking
  requests and responses instead of simply replacing the
  ``GoogleOAuth2Client`` for testing.
- Moved the ``BaseUser`` and ``BaseUserManager`` to
  ``authlib.base_user`` for consistency with
  ``django.contrib.auth.base_user``.
- Dropped the useless ``OAuthClient`` base class.
- Removed compatibility code for Django<1.11 when verifying whether a
  redirection URL is safe.
- Changed the ``retrieve_next`` implementations to only consider HTTPS
  URLs as safe when processing HTTPS requests.
- Changed the admin OAuth functionality to also use the cookies code
  from ``authlib.views`` for redirecting users after authentication.
- Fixed a possible crash in the Twitter OAuth flow when the token from
  the authentication redirect cannot be determined anymore.
- Fixed a crash in the OAuth2 view if fetching user data fails.


`0.8`_ (2018-11-17)
===================

- **BACKWARDS INCOMPATIBLE** Replaced the email registration
  functionality of referencing users with arbitrary payloads. This
  allows not only verifying the email address but also additional data
  which may or may not be related to the user in question. On the other
  hand the comparison of ``last_login`` timestamps is gone, which means
  that links may be reused as long as less than ``max_age`` seconds have
  passed. This makes it even more important to keep ``max_age`` small.
  The change mostly affects the functions in ``authlib.email``.


`0.7`_ (2018-11-04)
===================

- Fixed a race condition when creating new users by using
  ``get_or_create`` instead of some homegrown ``exists`` and
  ``create`` trickery.
- Changed all locations to pass ``new_user`` as keyword argument to
  ``post_login_response``.
- Changed the ``admin/login.html`` template in ``authlib.admin_oauth``
  to make the SSO button a bit more prominent. Also, replaced "SSO" with
  "Google" because that is all that is supported right now.
- Added the possibility to use callables in ``ADMIN_OAUTH_PATTERNS``
  instead of hard-coded staff email addresses.
- Extracted the confirmation code generation from
  ``get_confirmation_url`` as ``get_confirmation_code``.
- Fixed usage of deprecated Google OAuth2 scopes.
- Added compatibility with Python 2.
- Extracted the post login redirect cookie setting into a new
  ``set_next_cookie`` decorator.
- Dropped compatibility shims for Django<1.11.
- Changed the ``EmailBackend`` to use ``_default_manager`` instead of
  assuming that the default manager is called ``objects``.
- Fixed an edge case bug where ``render_to_mail`` would crash when
  encountering an empty text for the subject and body.
- Enforced keyword-only usage of the views and functions in
  ``authlib.views`` where it is appropriate.
- Removed the default messages emitted when creating a new user and when
  logging out.
- Added a ``post_logout_response`` callable and argument to
  ``authlib.views.logout`` to customize messages and redirects after
  logging an user out.
- Added a ``email_login`` callable and argument to the ``oauth2`` and
  ``email_registration`` view to customize the creation, authentication
  and login of users.
- Changed the ``EmailRegistrationForm`` to save the request as
  ``self.request``, not ``self._request``. Made use of this for moving
  the email sending to the form class as well, further shortening the
  view.


`0.6`_ (2017-12-04)
===================

- Fixed usage of a few deprecated APIs.
- Modified ``little_auth.User`` to fall back to an obfuscated email
  address if the full name is empty.
- Made it possible to override the default max age of three hours for
  magic links sent by email.
- Fixed a problem where the ``little_auth`` migrations were depending on
  the latest ``django.contrib.auth`` migration instead of the first
  migration without good reason.


`0.5`_ (2017-05-17)
===================

- Moved from ``ADMIN_OAUTH_DOMAINS`` to ``ADMIN_OAUTH_PATTERNS`` to
  allow regular expression searching.
- Finally started adding tests.
- Added django-authlib_ documentation to Read the Docs.


`0.4`_ (2017-05-11)
===================

- Added some documentation to the README.
- Google client: Removed the deprecated profile scope, and switched to
  online access only (we do not need offline access).
- Added the ``authlib.admin_oauth`` app for a minimal Google OAuth2
  authentication solution for Django's administration interface.
- Added the ``authlib.little_auth`` app containing a minimal user model
  with email as username for a quick and dirty ``auth.User``
  replacement.
- Allow overriding the view name used in
  ``authlib.email.get_confirmation_url``.


`0.3`_ (2016-12-08)
===================

- Fixed the redirect URL generation of the Facebook and Google client.
- Changed the name of the post login redirect cookie from ``next`` to
  ``authlib-next`` to hopefully prevent clashes.
- Authentication providers may also return ``None`` as email address;
  handle this case gracefully by showing an error message instead of
  crashing.
- Pass full URLs, not only paths to the OAuth2 libraries because
  otherwise, secure redirect URLs aren't recognized as such.


`0.2`_ (2016-11-22)
===================

- Added views for registration and logging in and out.
- Added a base user model and an authentication backend for
  authenticating using email addresses only.


`0.1`_ (2016-11-21)
===================

- Initial release containing helpers for authentication using an email
  address, either verified by sending a magic link or retrieved from
  Facebook, Google or Twitter.

.. _django-authlib: https://django-authlib.readthedocs.io/

.. _0.1: https://github.com/matthiask/django-authlib/commit/0e4a81c11
.. _0.2: https://github.com/matthiask/django-authlib/compare/0.1...0.2
.. _0.3: https://github.com/matthiask/django-authlib/compare/0.2...0.3
.. _0.4: https://github.com/matthiask/django-authlib/compare/0.3...0.4
.. _0.5: https://github.com/matthiask/django-authlib/compare/0.4...0.5
.. _0.6: https://github.com/matthiask/django-authlib/compare/0.5...0.6
.. _0.7: https://github.com/matthiask/django-authlib/compare/0.6...0.7
.. _0.8: https://github.com/matthiask/django-authlib/compare/0.7...0.8
.. _0.9: https://github.com/matthiask/django-authlib/compare/0.8...0.9
.. _0.10: https://github.com/matthiask/django-authlib/compare/0.9...0.10
.. _0.11: https://github.com/matthiask/django-authlib/compare/0.10...0.11

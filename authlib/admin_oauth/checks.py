"""
System checks for the admin single sign-on setup.

The ``ADMIN_OAUTH_PATTERNS`` setting comes first, the checks for
``authlib.admin_oauth.passwords.disable_passwords`` are at the end of the
module. Both share a motivation: their failure modes are silent, and they fail
in the direction of not letting anyone in, respectively of still allowing
passwords.

Callables in ``ADMIN_OAUTH_PATTERNS`` receive the ``re.Match`` object, not the
email address, which makes ``lambda match: match[0]`` a trap: it only produces
a full address if the pattern matches the *whole* address. Configure
``(r"@example\\.com$", lambda match: match[0])`` and the callable returns
``"@example.com"``, which cannot possibly belong to a user -- so nobody from
that domain can ever authenticate.

We cannot reason about what a callable does, but we can run it: build an
example address the pattern matches, hand the match to the callable, and check
that what comes back looks like an email address at all. Building the example
means generating a string from the parsed regex, which only works for the
uncomplicated patterns people actually write here; anything else (lookarounds,
backreferences, ...) is skipped silently. Generated examples are verified
against the pattern before being used, so a bad example produces no output
instead of a bogus check failure.
"""

import re

from django.conf import settings
from django.core.checks import Error, Warning, register
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.urls import get_resolver


try:  # Python 3.11 and better
    from re import _parser as _re_parser
except ImportError:  # pragma: no cover
    import sre_parse as _re_parser


__all__ = ["check_admin_oauth_patterns", "check_disabled_passwords"]

_CALLABLE_HINT = (
    "Callables receive the re.Match object, so match[0] is only the part of"
    ' the address matched by the pattern: r"@example\\.com$" matches'
    ' "@example.com", not the whole address. Either anchor the pattern so that'
    ' it matches the complete address (r"^.*@example\\.com$") or use'
    " match.string to get at the address which was matched."
)

# Characters used when the pattern doesn't dictate a specific one.
_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789.-_+"
# An example address may need a local part and/or a domain around whatever the
# pattern itself matches; unanchored patterns are the norm, not the exception.
_PREFIXES = ("", "probe", "probe@")
_SUFFIXES = ("", "com", "@example.com")

_CATEGORIES = {
    "CATEGORY_DIGIT": str.isdigit,
    "CATEGORY_SPACE": str.isspace,
    "CATEGORY_WORD": lambda char: char.isalnum() or char == "_",
}


class _UnsupportedError(Exception):
    """The pattern contains something we cannot generate an example for."""


def _category_matches(category, char):
    if positive := _CATEGORIES.get(category):
        return positive(char)
    if positive := _CATEGORIES.get(category.replace("CATEGORY_NOT_", "CATEGORY_")):
        return not positive(char)
    raise _UnsupportedError


def _set_matches(items, char):
    for op, av in items:
        name = op.name
        if name == "LITERAL":
            if ord(char) == av:
                return True
        elif name == "RANGE":
            if av[0] <= ord(char) <= av[1]:
                return True
        elif name == "CATEGORY":
            if _category_matches(av.name, char):
                return True
        else:
            raise _UnsupportedError
    return False


def _example_for_set(items):
    """Return a character matching the ``[...]`` set described by ``items``."""
    if items and items[0][0].name == "NEGATE":
        items = items[1:]
        wanted = False
    else:
        wanted = True
    for char in _ALPHABET:
        if _set_matches(items, char) is wanted:
            return char
    raise _UnsupportedError


def _example_for_branch(branches):
    for branch in branches:
        try:
            return _example(branch)
        except _UnsupportedError:
            continue
    raise _UnsupportedError


def _example(sequence):
    """Return a string matching the parsed regex ``sequence``."""
    parts = []
    for op, av in sequence:
        name = op.name
        if name == "LITERAL":
            parts.append(chr(av))
        elif name == "NOT_LITERAL":
            parts.append(next(char for char in _ALPHABET if ord(char) != av))
        elif name == "ANY":
            parts.append(_ALPHABET[0])
        elif name == "IN":
            parts.append(_example_for_set(av))
        elif name in {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}:
            minimum, maximum, item = av
            # Prefer one repetition over zero: ".*" should contribute a
            # character, or "^(.*)@example\\.com$" would produce an address
            # without a local part.
            parts.append(_example(item) * min(max(minimum, 1), maximum))
        elif name == "SUBPATTERN":
            parts.append(_example(av[-1]))
        elif name == "ATOMIC_GROUP":
            parts.append(_example(av))
        elif name == "BRANCH":
            parts.append(_example_for_branch(av[1]))
        elif name == "AT":
            pass  # Anchors do not contribute characters.
        else:
            raise _UnsupportedError
    return "".join(parts)


def _is_email(value):
    if not isinstance(value, str):
        return False
    try:
        validate_email(value)
    except ValidationError:
        return False
    return True


def _example_address(pattern):
    """Return an email address matching ``pattern``, or ``None``."""
    try:
        core = _example(_re_parser.parse(pattern))
    except Exception:
        # _UnsupportedError, or anything at all from the private regex parser.
        return None
    for prefix in _PREFIXES:
        for suffix in _SUFFIXES:
            address = f"{prefix}{core}{suffix}"
            if _is_email(address) and re.search(pattern, address):
                return address
    return None


def _check_callable(where, pattern, target):
    address = _example_address(pattern)
    if address is None:
        # We cannot build an example address, so there's nothing to verify.
        return []

    try:
        result = target(re.search(pattern, address))
    except Exception as exc:
        return [
            Warning(
                f"{where} raised {exc!r} when called with the match for the"
                f" example address {address!r}.",
                hint=_CALLABLE_HINT,
                id="authlib.W001",
            )
        ]

    if result is None:
        return [
            Warning(
                f"{where} returned None for the example address {address!r},"
                " which never authenticates anyone.",
                hint=_CALLABLE_HINT,
                id="authlib.W002",
            )
        ]

    if not _is_email(result):
        return [
            Error(
                f"{where} returned {result!r} for the example address"
                f" {address!r}, which is not an email address. No user can"
                " ever match, so this pattern never authenticates anyone.",
                hint=_CALLABLE_HINT,
                id="authlib.E004",
            )
        ]
    return []


def _check_entry(index, entry):
    where = f"ADMIN_OAUTH_PATTERNS[{index}]"
    try:
        pattern, target = entry
    except (TypeError, ValueError):
        return [
            Error(
                f"{where} is not a (pattern, email address or callable) pair.",
                id="authlib.E002",
            )
        ]

    try:
        re.compile(pattern)
    except (re.error, TypeError) as exc:
        return [
            Error(
                f"{where} contains an invalid regular expression: {exc}",
                id="authlib.E003",
            )
        ]

    if callable(target):
        return _check_callable(where, pattern, target)
    if not _is_email(target):
        return [
            Error(
                f"{where} maps to {target!r}, which is not an email address.",
                hint="The second item of each pair is the email address of a"
                " staff user, or a callable returning one.",
                id="authlib.E004",
            )
        ]
    return []


@register()
def check_admin_oauth_patterns(app_configs, **kwargs):
    patterns = getattr(settings, "ADMIN_OAUTH_PATTERNS", None)
    if patterns is None:
        return [
            Error(
                "The ADMIN_OAUTH_PATTERNS setting is required by authlib.admin_oauth.",
                id="authlib.E001",
            )
        ]
    try:
        entries = list(enumerate(patterns))
    except TypeError:
        return [
            Error(
                "The ADMIN_OAUTH_PATTERNS setting must be a list of"
                f" (pattern, email address or callable) pairs, not {patterns!r}.",
                id="authlib.E002",
            )
        ]
    return [error for index, entry in entries for error in _check_entry(index, entry)]


def _url_patterns():
    """The root URLconf's patterns, or ``None`` if it cannot be loaded.

    Loading the URLconf is also what runs the project's ``disable_passwords()``
    call, so this has to happen before looking at the list of admin sites which
    have had their passwords disabled. Django's own checks report a URLconf
    which cannot be loaded; we say nothing at all in that case.
    """
    try:
        return get_resolver().url_patterns
    except Exception:
        return None


def _walk(patterns, prefix=""):
    """Yield ``(route, url_pattern)`` pairs for the whole URLconf tree."""
    for pattern in patterns:
        route = f"{prefix}{pattern.pattern}"
        if hasattr(pattern, "url_patterns"):  # A URLResolver, i.e. include()
            yield from _walk(pattern.url_patterns, route)
        else:
            yield route, pattern


def _password_management_urls(patterns):
    """Routes of the views which set a password for an existing user."""
    from django.contrib.auth.views import (  # noqa: PLC0415
        PasswordChangeView,
        PasswordResetConfirmView,
        PasswordResetView,
    )

    views = (PasswordChangeView, PasswordResetConfirmView, PasswordResetView)
    for route, pattern in _walk(patterns):
        view_class = getattr(pattern.callback, "view_class", None)
        if isinstance(view_class, type) and issubclass(view_class, views):
            yield route, view_class


def _password_change_views(patterns, site):
    """The views behind the admin site's password change URLs, as they ended up
    in the URLconf.

    ``AdminSite.get_urls`` hands each view to ``functools.update_wrapper``,
    which is why the wrapper in the URLconf still knows the view it was built
    from (``__wrapped__``) and the site it belongs to (``admin_site``).
    """
    for _route, pattern in _walk(patterns):
        callback = pattern.callback
        if (
            pattern.name == "password_change"
            and getattr(callback, "admin_site", None) is site
            and hasattr(callback, "__wrapped__")
        ):
            yield callback.__wrapped__


def _check_site(site, patterns):
    from django.template.loader import get_template  # noqa: PLC0415

    messages = []
    for attribute in ("login_template", "password_change_template"):
        if not (template := getattr(site, attribute, None)):
            continue
        try:
            get_template(template)
        except Exception:
            messages.append(
                Error(
                    f"The template {template!r} configured as {attribute} of"
                    f" the {site.name!r} admin site cannot be loaded.",
                    hint=(
                        "disable_passwords() points the admin site at templates"
                        ' which ship with authlib.admin_oauth; add "authlib.admin_oauth"'
                        " to INSTALLED_APPS, or pass templates of your own"
                        " (disable_passwords(site, login_template=...))."
                    ),
                    id="authlib.E011",
                )
            )

    if any(
        view is not site.password_change
        for view in _password_change_views(patterns, site)
    ):
        messages.append(
            Error(
                f"The password change URL of the {site.name!r} admin site still"
                " points at Django's own view: disable_passwords() ran after"
                " the site's URLs had been built, so passwords can still be"
                " changed there.",
                hint=(
                    "Call disable_passwords(site) before including site.urls in"
                    " the URLconf -- at the top of the ROOT_URLCONF module, or"
                    " in an admin.py, which is imported while the apps are"
                    " loading."
                ),
                id="authlib.E012",
            )
        )
    return messages


@register()
def check_disabled_passwords(app_configs, **kwargs):
    from authlib.admin_oauth import passwords  # noqa: PLC0415

    patterns = _url_patterns()
    if patterns is None or not passwords._disabled_sites:
        return []

    messages = [
        message
        for site in passwords._disabled_sites
        for message in _check_site(site, patterns)
    ]

    if urls := sorted(_password_management_urls(patterns), key=lambda url: url[0]):
        messages.append(
            Warning(
                "Passwords are disabled on the Django admin site, but the"
                " URLconf still contains views which set passwords: "
                + ", ".join(
                    f"{route!r} ({view_class.__name__})" for route, view_class in urls
                )
                + ".",
                hint=(
                    "Staff users can get themselves a password through those"
                    " views and use it wherever password logins are still"
                    " accepted -- and any active staff session gets into the"
                    " admin, whether or not the admin's login form created it."
                    " Remove those URLs unless users of this site need"
                    " passwords outside of the admin; if they do, silence this"
                    ' check with SILENCED_SYSTEM_CHECKS = ["authlib.W003"].'
                ),
                id="authlib.W003",
            )
        )

    return messages

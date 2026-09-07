"""
System checks for the ``ADMIN_OAUTH_PATTERNS`` setting.

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


try:  # Python 3.11 and better
    from re import _parser as _re_parser
except ImportError:  # pragma: no cover
    import sre_parse as _re_parser


__all__ = ["check_admin_oauth_patterns"]

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

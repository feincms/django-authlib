"""
System check for the ``PermissionsBackend`` rename.

Django loads ``AUTHENTICATION_BACKENDS`` lazily, so a stale path in there
only blows up (``ImproperlyConfigured``) once something touches
authentication -- during a request, most likely, and with a message that
explains nothing about what to do. Reporting it as a system check instead
means ``manage.py check`` and every management command refuse to run until
the setting is updated, and the message can say what changed and why.
"""

from django.conf import settings
from django.core.checks import Error, register


__all__ = ["check_authentication_backends"]

LEGACY_PATH = "authlib.backends.PermissionsBackend"
CURRENT_PATH = "authlib.backends.RolePermissionsBackend"


@register()
def check_authentication_backends(app_configs, **kwargs):
    backends = getattr(settings, "AUTHENTICATION_BACKENDS", [])
    if LEGACY_PATH not in backends:
        return []
    return [
        Error(
            f"AUTHENTICATION_BACKENDS contains {LEGACY_PATH!r}, which doesn't"
            f" exist anymore: the class is called {CURRENT_PATH!r} now, and it"
            " is a permissions backend only -- it does not authenticate"
            " anyone.",
            hint=(
                "Update the path. If your project has password logins, add"
                ' "django.contrib.auth.backends.ModelBackend" to'
                " AUTHENTICATION_BACKENDS as well: the old class extended"
                " ModelBackend, so password logins used to run through it"
                " rather than through whatever comes later in the list."
                " Everybody is logged out once, since sessions record the"
                " backend which authenticated them."
            ),
            id="authlib.E010",
        )
    ]

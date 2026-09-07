"""
Take passwords away from a Django admin site.

Single sign-on with an identity provider which enforces MFA is only worth
something if a password can't be used instead, so ``disable_passwords`` closes
the two places where the admin site itself deals with passwords: the login form
and the password change view.

A form is the right place for the login part: ``AdminSite`` is the only consumer
of ``login_form``, so nothing outside the admin is affected, and
``AuthenticationForm.clean()`` is where ``authenticate()`` is called -- refusing
there means no password ever reaches an authentication backend. An
authentication backend cannot do this job: ``authenticate()`` is global, and a
backend has no reliable way of knowing whether it is being called for the admin
login form or for something else.

The password change page is closed by replacing ``AdminSite.password_change``.
``AdminSite.password_change_form`` only exists in Django 6.0 and better, so
setting it (which we do as well, see below) wouldn't do anything at all on the
Django versions most projects are running.

Only the admin site is affected. Everything else which can set a password keeps
working: ``django.contrib.auth``'s password change and password reset views, the
user admin's "change password" form, ``manage.py changepassword``. The system
checks in ``authlib.admin_oauth.checks`` warn about the URLs among those, since
an active staff session gets into the admin whether or not the admin's login
form created it (``AdminSite.has_permission`` only looks at ``is_active`` and
``is_staff``).
"""

from django.contrib.admin.forms import AdminAuthenticationForm, AdminPasswordChangeForm
from django.core.exceptions import ValidationError
from django.template.response import TemplateResponse
from django.utils.translation import gettext_lazy as _


__all__ = [
    "PasswordChangeDisabledForm",
    "PasswordLoginDisabledForm",
    "disable_passwords",
]

LOGIN_TEMPLATE = "admin_oauth/login.html"
PASSWORD_CHANGE_TEMPLATE = "admin_oauth/password_change.html"

# Admin sites which have been through disable_passwords(), for the sake of the
# system checks. Identity is what matters here, and there are never more than a
# few admin sites, so a list will do.
_disabled_sites = []


class PasswordLoginDisabledForm(AdminAuthenticationForm):
    """Admin login form which refuses to authenticate anyone.

    The fields are removed, not just ignored: the login page shouldn't ask for
    a password it is going to throw away, and a password which is never
    rendered as an input is a password which doesn't end up in the browser's
    password manager or in a POST body.
    """

    error_messages = {
        **AdminAuthenticationForm.error_messages,
        "passwords_disabled": _(
            "Password authentication is disabled. Please use single sign-on to log in."
        ),
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields.clear()

    def clean(self):
        raise ValidationError(
            self.error_messages["passwords_disabled"], code="passwords_disabled"
        )


class PasswordChangeDisabledForm(AdminPasswordChangeForm):
    """Password change form which refuses to change anything.

    Django 6.0 added ``AdminSite.password_change_form``; on older versions the
    view replacement in ``disable_passwords`` is all there is.
    """

    error_messages = {
        **AdminPasswordChangeForm.error_messages,
        "passwords_disabled": _(
            "Password authentication is disabled, so passwords cannot be changed."
        ),
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields.clear()

    def clean(self):
        raise ValidationError(
            self.error_messages["passwords_disabled"], code="passwords_disabled"
        )


def _password_change_disabled(site):
    def password_change(request, extra_context=None):
        """``AdminSite.password_change``, minus the password change."""
        request.current_app = site.name
        return TemplateResponse(
            request,
            site.password_change_template,
            {
                **site.each_context(request),
                "title": _("Password change"),
                "message": PasswordChangeDisabledForm.error_messages[
                    "passwords_disabled"
                ],
                **(extra_context or {}),
            },
        )

    return password_change


def disable_passwords(
    site,
    *,
    login_template=LOGIN_TEMPLATE,
    password_change_template=PASSWORD_CHANGE_TEMPLATE,
):
    """Disable password logins and password changes on an admin site.

    Call this before the site's URLs are built, which means at the top of the
    ROOT_URLCONF module, or in any ``admin.py`` (those are imported while the
    apps are loading):

    .. code-block:: python

        from django.contrib import admin
        from authlib.admin_oauth.passwords import disable_passwords

        disable_passwords(admin.site)

        urlpatterns = [path("admin/", admin.site.urls), ...]

    Pass ``login_template`` and/or ``password_change_template`` to use your own
    templates instead of the ones shipped with ``authlib.admin_oauth``.

    Passwords remain usable everywhere else; see the module docstring and the
    ``authlib.W003`` system check.
    """
    site.login_form = PasswordLoginDisabledForm
    # ``None`` means "Django's own login template" and is a valid choice for a
    # project bringing its own admin/login.html. The password change template
    # has no such fallback: it is what our replacement view renders.
    site.login_template = login_template
    site.password_change_template = password_change_template or PASSWORD_CHANGE_TEMPLATE
    # Ignored before Django 6.0. It still matters on newer versions if
    # disable_passwords() ran too late for the view replacement below to make
    # it into the URLconf -- authlib.E012 reports that case.
    site.password_change_form = PasswordChangeDisabledForm
    site.password_change = _password_change_disabled(site)
    if not any(disabled is site for disabled in _disabled_sites):
        _disabled_sites.append(site)
    return site

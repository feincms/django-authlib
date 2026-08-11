from fnmatch import fnmatch

from django import forms
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import models
from django.utils.translation import gettext_lazy as _


def allow_deny_globs(user, perm, obj, allow=(), deny=()):
    if any(fnmatch(perm, rule) for rule in deny):
        raise PermissionDenied
    return any(fnmatch(perm, rule) for rule in allow)


DEFAULT_ROLES = {
    "default": {
        "title": _("default"),
    },
}


def _roles():
    return getattr(settings, "AUTHLIB_ROLES", DEFAULT_ROLES)


class RoleField(models.CharField):
    def __init__(self, *args, **kwargs):
        choices = [(key, cfg["title"]) for key, cfg in _roles().items()]
        kwargs = kwargs | {
            "choices": choices,
            "default": choices[0][0],
            "max_length": 100,
            "verbose_name": _("role"),
        }
        super().__init__(*args, **kwargs)

    def contribute_to_class(self, cls, name):
        super().contribute_to_class(cls, name)

        def _role_has_perm(self, *, perm, obj):
            if (r := _roles().get(getattr(self, name))) and (cb := r.get("callback")):
                return self.is_active and cb(user=self, perm=perm, obj=obj)

        cls._role_has_perm = _role_has_perm

    def deconstruct(self):
        name, _path, args, kwargs = super().deconstruct()
        kwargs["choices"] = [("", "")]
        return name, "django.db.models.CharField", args, kwargs

    def formfield(self, **kwargs):
        if len(self.choices) <= 1:
            kwargs.setdefault("initial", self.choices[0][0])
            kwargs.setdefault("widget", forms.HiddenInput)
        return super().formfield(**kwargs)

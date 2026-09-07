from django.apps import AppConfig
from django.utils.text import capfirst
from django.utils.translation import gettext_lazy as _


class LittleAuthConfig(AppConfig):
    name = "authlib.little_auth"
    default_auto_field = "django.db.models.AutoField"
    verbose_name = capfirst(_("Authentication"))

    def ready(self):
        from authlib import checks  # noqa: F401,PLC0415

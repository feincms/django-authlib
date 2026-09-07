from django.apps import AppConfig


class AdminOAuthConfig(AppConfig):
    name = "authlib.admin_oauth"
    label = "admin_oauth"

    def ready(self):
        from authlib import checks as authlib_checks  # noqa: F401,PLC0415
        from authlib.admin_oauth import checks  # noqa: F401,PLC0415

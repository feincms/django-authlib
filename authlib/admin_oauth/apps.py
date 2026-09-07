from django.apps import AppConfig


class AdminOAuthConfig(AppConfig):
    name = "authlib.admin_oauth"
    label = "admin_oauth"

    def ready(self):
        from authlib.admin_oauth import checks  # noqa: F401,PLC0415

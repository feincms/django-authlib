from django.apps import AppConfig


class AuthlibConfig(AppConfig):
    name = "authlib"

    def ready(self):
        from authlib import checks  # noqa: F401,PLC0415

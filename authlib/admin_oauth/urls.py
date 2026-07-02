from django.urls import path

from authlib.admin_oauth.views import admin_oauth
from authlib.google import GoogleOAuth2Client
from authlib.microsoft import MicrosoftOAuth2Client


urlpatterns = [
    path(
        "admin/__oauth__/",
        admin_oauth,
        name="admin_oauth",
        kwargs={"client_class": GoogleOAuth2Client},
    ),
    path(
        "admin/__oauth_ms__/",
        admin_oauth,
        name="admin_oauth_microsoft",
        kwargs={"client_class": MicrosoftOAuth2Client},
    ),
]

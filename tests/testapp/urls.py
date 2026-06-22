from django.contrib import admin
from django.shortcuts import render
from django.urls import include, path, re_path

from authlib import views
from authlib.facebook import FacebookOAuth2Client
from authlib.google import GoogleOAuth2Client
from authlib.microsoft import MicrosoftOAuth2Client
from authlib.twitter import TwitterOAuthClient
from testapp.views import custom_verification, custom_verification_code


urlpatterns = [
    path("", include("authlib.admin_oauth.urls")),
    re_path(r"^admin/", admin.site.urls),
    path("404/", lambda request: render(request, "404.html")),
    path("login/", views.login, name="login"),
    path(
        "oauth/facebook/",
        views.oauth2,
        {"client_class": FacebookOAuth2Client},
        name="accounts_oauth_facebook",
    ),
    path(
        "oauth/google/",
        views.oauth2,
        {"client_class": GoogleOAuth2Client},
        name="accounts_oauth_google",
    ),
    path(
        "oauth/microsoft/",
        views.oauth2,
        {"client_class": MicrosoftOAuth2Client},
        name="accounts_oauth_microsoft",
    ),
    path(
        "oauth/twitter/",
        views.oauth2,
        {"client_class": TwitterOAuthClient},
        name="accounts_oauth_twitter",
    ),
    path("email/", views.email_registration, name="email_registration"),
    path(
        "email/<str:code>/",
        views.email_registration,
        name="email_registration_confirm",
    ),
    path("logout/", views.logout, name="logout"),
    path("custom/", custom_verification),
    path(
        "custom/<str:code>/",
        custom_verification_code,
        name="custom_verification_code",
    ),
]

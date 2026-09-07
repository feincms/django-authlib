"""URLconf for an admin site without passwords, see test_passwords.py."""

from django.contrib.admin.sites import AdminSite
from django.urls import include, path

from authlib.admin_oauth.passwords import disable_passwords
from authlib.little_auth.models import User


site = AdminSite()
site.register(User)
disable_passwords(site)

urlpatterns = [
    path("", include("authlib.admin_oauth.urls")),
    path("admin/", site.urls),
]

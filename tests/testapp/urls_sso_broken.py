"""URLconf which gets everything wrong, see test_passwords.py."""

from django.contrib.admin.sites import AdminSite
from django.urls import include, path

from authlib.admin_oauth.passwords import disable_passwords


site = AdminSite(name="broken")

urlpatterns = [
    path("admin/", site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
]

# Too late: the site's URLs have been built by the time we get here.
disable_passwords(site)

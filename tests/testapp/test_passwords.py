from unittest.mock import patch

from django.contrib.admin.sites import AdminSite
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils.translation import deactivate_all

from authlib.admin_oauth import passwords
from authlib.admin_oauth.checks import check_disabled_passwords
from authlib.admin_oauth.passwords import disable_passwords
from authlib.little_auth.models import User
from testapp.test_authlib import google_oauth_data, start_oauth


@override_settings(ROOT_URLCONF="testapp.urls_sso")
class DisabledPasswordsTest(TestCase):
    def setUp(self):
        deactivate_all()
        self.user = User.objects.create_superuser("admin@example.com", "blabla")

    def test_login_page_has_no_credential_inputs(self):
        """Nothing of the login form remains, single sign-on stays."""
        response = self.client.get("/admin/login/")
        self.assertNotContains(response, 'name="username"')
        self.assertNotContains(response, 'name="password"')
        self.assertContains(response, "#login-form {")
        self.assertContains(response, "Log in using Google")

    def test_password_login_is_refused(self):
        self.assertTrue(self.user.check_password("blabla"))

        response = self.client.post(
            "/admin/login/",
            {"username": "admin@example.com", "password": "blabla"},
        )
        self.assertContains(response, "Password authentication is disabled.")
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertRedirects(self.client.get("/admin/"), "/admin/login/?next=/admin/")

    def test_single_sign_on_still_works(self):
        state = start_oauth(self.client, "/admin/__oauth__/")
        with google_oauth_data({"email": "admin@example.com", "email_verified": True}):
            response = self.client.get(f"/admin/__oauth__/?code=bla&state={state}")
        self.assertRedirects(response, "/admin/")
        self.assertEqual(self.client.get("/admin/little_auth/").status_code, 200)

    def test_password_change_page_only_explains_itself(self):
        self.client.force_login(self.user)
        response = self.client.get("/admin/password_change/")
        self.assertContains(response, "passwords cannot be changed")
        self.assertNotContains(response, 'type="password"')

    def test_password_change_changes_nothing(self):
        self.client.force_login(self.user)
        response = self.client.post(
            "/admin/password_change/",
            {
                "old_password": "blabla",
                "new_password1": "verysecret123",
                "new_password2": "verysecret123",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("blabla"))


class ChecksTest(SimpleTestCase):
    def test_no_disabled_sites(self):
        """Projects which do not call disable_passwords() hear nothing."""
        with patch.object(passwords, "_disabled_sites", []):
            self.assertEqual(check_disabled_passwords(app_configs=None), [])

    @override_settings(ROOT_URLCONF="testapp.urls_sso")
    def test_disabled_site(self):
        self.assertEqual(check_disabled_passwords(app_configs=None), [])

    @override_settings(ROOT_URLCONF="testapp.urls_sso_broken")
    def test_late_call_and_password_urls(self):
        messages = check_disabled_passwords(app_configs=None)
        self.assertEqual(
            {message.id for message in messages}, {"authlib.E012", "authlib.W003"}
        )

        (error,) = [message for message in messages if message.id == "authlib.E012"]
        self.assertIn("'broken' admin site", error.msg)

        (warning,) = [message for message in messages if message.id == "authlib.W003"]
        self.assertIn("'accounts/password_change/' (PasswordChangeView)", warning.msg)
        self.assertIn("'accounts/password_reset/' (PasswordResetView)", warning.msg)
        self.assertIn("(PasswordResetConfirmView)", warning.msg)

    def test_missing_templates(self):
        with patch.object(passwords, "_disabled_sites", []):
            disable_passwords(
                AdminSite(name="missing"),
                login_template="no-such-login.html",
                password_change_template="no-such-password-change.html",
            )
            messages = check_disabled_passwords(app_configs=None)

        self.assertEqual(
            [message.id for message in messages], ["authlib.E011", "authlib.E011"]
        )
        self.assertIn("'no-such-login.html'", messages[0].msg)
        self.assertIn("login_template", messages[0].msg)

import base64
import json
from contextlib import contextmanager
from unittest import skipUnless
from unittest.mock import patch
from urllib.parse import parse_qsl, urlparse

import requests_mock
from django.conf import settings
from django.contrib.sessions.backends.db import SessionStore
from django.test import Client, RequestFactory, TestCase
from django.test.utils import isolate_apps, modify_settings
from django.utils.translation import deactivate_all

from authlib.base_user import BaseUser
from authlib.facebook import FacebookOAuth2Client
from authlib.little_auth.models import User
from authlib.microsoft import MICROSOFT_OAUTH_STATE_SESSION_KEY, MicrosoftOAuth2Client


try:
    from django.contrib.auth.middleware import LoginRequiredMiddleware  # noqa: F401

    has_login_required_middleware = True
except ImportError:
    # Django < 5.1
    has_login_required_middleware = False


@contextmanager
def google_oauth_data(data):
    with requests_mock.Mocker() as m:
        jwt = (
            base64.urlsafe_b64encode(json.dumps(data).encode("utf-8"))
            .replace(b"=", b"")
            .decode("utf-8")
        )
        m.post(
            "https://www.googleapis.com/oauth2/v4/token",
            json={
                "access_token": "123",
                "id_token": f"header.{jwt}.signature",
            },
        )
        yield


@contextmanager
def google_oauth_authentication_url():
    with requests_mock.Mocker() as m:
        m.get("https://accounts.google.com/o/oauth2/v2/auth", {})
        yield


def start_oauth(client, url):
    """
    Performs the "start" leg of an OAuth2 login (the redirect to the
    provider) and returns the ``state`` value the provider would echo back
    in the callback. Real browsers always do this round-trip; tests have to
    simulate it explicitly now that ``state`` is actually validated.
    """
    response = client.get(url)
    return dict(parse_qsl(urlparse(response["Location"]).query))["state"]


class Test(TestCase):
    def setUp(self):
        deactivate_all()
        self.user = User.objects.create_superuser("admin@example.com", "blabla")

    def test_manager(self):
        with self.assertRaises(TypeError):
            User.objects.create_user()
        with self.assertRaises(ValueError):
            User.objects.create_user(None)
        with self.assertRaises(ValueError):
            User.objects.create_user("")

    @isolate_apps("authlib")
    def test_user(self):
        class User(BaseUser):
            pass

        user = User(email="test@example.com")
        self.assertEqual(f"{user}", "test@example.com")
        self.assertEqual(user.get_full_name(), "test@example.com")
        self.assertEqual(user.get_short_name(), "test@example.com")

    def test_admin_oauth(self):
        client = Client()

        response = client.get("/admin/login/?next=/admin/little_auth/")
        self.assertContains(
            response,
            '<a class="button" href="/admin/__oauth__/?next=/admin/little_auth/">Log in using Google</a>',
        )

        response = client.get("/admin/__oauth__/?next=/admin/little_auth/")
        self.assertEqual(response.status_code, 302)
        self.assertIn(
            "https://accounts.google.com/o/oauth2/v2/auth?response_type=code"
            "&client_id=empty&redirect_uri=",
            response["Location"],
        )
        state = dict(parse_qsl(urlparse(response["Location"]).query))["state"]

        with google_oauth_data({"email": "blaaa@example.com", "email_verified": True}):
            response = client.get(f"/admin/__oauth__/?code=bla&state={state}")
        self.assertRedirects(response, "/admin/little_auth/")

        self.assertEqual(client.get("/admin/little_auth/").status_code, 200)

    @patch.object(settings, "GOOGLE_CLIENT_ID", None)
    @patch.object(settings, "MICROSOFT_CLIENT_ID", None)
    def test_admin_login_buttons_without_credentials(self, *mocks):
        """Test that OAuth buttons are not displayed when credentials are not provided."""
        client = Client()
        response = client.get("/admin/login/")

        # Google button should not be present when GOOGLE_CLIENT_ID is None
        self.assertNotContains(
            response,
            '<a class="button" href="/admin/__oauth__/',
        )
        self.assertNotContains(response, "Log in using Google")

        # Microsoft button should not be present when MICROSOFT_CLIENT_ID is None
        self.assertNotContains(
            response,
            '<a class="button" href="/admin/__oauth_ms__/',
        )
        self.assertNotContains(response, "Log in using Microsoft")

    @patch.object(settings, "GOOGLE_CLIENT_ID", "test_google_id")
    @patch.object(settings, "GOOGLE_CLIENT_SECRET", "test_google_secret")
    @patch.object(settings, "MICROSOFT_CLIENT_ID", "test_microsoft_id")
    @patch.object(settings, "MICROSOFT_CLIENT_SECRET", "test_microsoft_secret")
    def test_admin_login_buttons_with_credentials(self, *mocks):
        """Test that OAuth buttons are displayed when credentials are provided."""
        client = Client()
        response = client.get("/admin/login/")

        # Google button should be present when GOOGLE_CLIENT_ID is set
        self.assertContains(
            response,
            '<a class="button" href="/admin/__oauth__/?next=',
        )
        self.assertContains(response, "Log in using Google")

        # Microsoft button should be present when MICROSOFT_CLIENT_ID is set
        self.assertContains(
            response,
            '<a class="button" href="/admin/__oauth_ms__/?next=',
        )
        self.assertContains(response, "Log in using Microsoft")

    def test_admin_oauth_no_data(self):
        client = Client()
        state = start_oauth(client, "/admin/__oauth__/")
        with google_oauth_data({}):
            response = client.get(f"/admin/__oauth__/?code=bla&state={state}")

        self.assertRedirects(response, "/admin/login/")

        messages = [str(m) for m in response.wsgi_request._messages]
        self.assertEqual(messages, ["Could not determine your email address."])

    def test_admin_oauth_match(self):
        client = Client()
        state = start_oauth(client, "/admin/__oauth__/")
        with google_oauth_data({"email": "admin@example.com", "email_verified": True}):
            response = client.get(f"/admin/__oauth__/?code=bla&state={state}")
        self.assertRedirects(response, "/admin/")

        # We are authenticated
        self.assertEqual(client.get("/admin/little_auth/").status_code, 200)

    def test_admin_oauth_nomatch(self):
        client = Client()
        state = start_oauth(client, "/admin/__oauth__/")
        with google_oauth_data({"email": "bla@example.org", "email_verified": True}):
            response = client.get(f"/admin/__oauth__/?code=bla&state={state}")

        # We are not authenticated
        self.assertRedirects(response, "/admin/login/")

        messages = [str(m) for m in response.wsgi_request._messages]
        self.assertEqual(
            messages, ["No matching staff users for email address 'bla@example.org'"]
        )

    @patch(
        "authlib.admin_oauth.views.ADMIN_OAUTH_PATTERNS",
        # A pattern which doesn't cover the local part: the callable returns
        # "@example.org", and no user can ever have that address.
        new=[(r"@example\.org$", lambda match: match[0])],
    )
    def test_admin_oauth_nomatch_logs_resolved_addresses(self):
        """
        The visitor is only told about their own address (the patterns and the
        addresses they produce are none of their business), the addresses which
        were actually looked up go to the log.
        """
        client = Client()
        state = start_oauth(client, "/admin/__oauth__/")
        with (
            google_oauth_data({"email": "bla@example.org", "email_verified": True}),
            self.assertLogs("authlib.admin_oauth", level="WARNING") as logs,
        ):
            response = client.get(f"/admin/__oauth__/?code=bla&state={state}")

        self.assertRedirects(response, "/admin/login/")

        messages = [str(m) for m in response.wsgi_request._messages]
        self.assertEqual(
            messages, ["No matching staff users for email address 'bla@example.org'"]
        )
        self.assertEqual(
            logs.output,
            [
                (
                    "WARNING:authlib.admin_oauth:No active staff user for"
                    " 'bla@example.org' (patterns produced '@example.org')"
                )
            ],
        )

    @patch(
        "authlib.admin_oauth.views.ADMIN_OAUTH_PATTERNS",
        new=[(r"@example\.com$", "admin@example.com")],
    )
    def test_admin_oauth_no_pattern_matches_at_all(self):
        client = Client()
        state = start_oauth(client, "/admin/__oauth__/")
        with (
            google_oauth_data({"email": "bla@example.org", "email_verified": True}),
            self.assertLogs("authlib.admin_oauth", level="WARNING") as logs,
        ):
            client.get(f"/admin/__oauth__/?code=bla&state={state}")

        self.assertEqual(
            logs.output,
            [
                (
                    "WARNING:authlib.admin_oauth:No active staff user for"
                    " 'bla@example.org' (patterns produced no addresses)"
                )
            ],
        )

    @patch(
        "authlib.admin_oauth.views.ADMIN_OAUTH_CREATE_USER_CALLBACK",
        new="authlib.admin_oauth.views.create_superuser",
    )
    @patch(
        "authlib.admin_oauth.views.ADMIN_OAUTH_PATTERNS",
        new=[
            (r"^.*@example\.com$", lambda match: match.group(0)),
        ],
    )
    def test_admin_oauth_user_created(self):
        client = Client()
        state = start_oauth(client, "/admin/__oauth__/")
        with google_oauth_data(
            {"email": "newuser@example.com", "email_verified": True}
        ):
            response = client.get(f"/admin/__oauth__/?code=bla&state={state}")
        self.assertRedirects(response, "/admin/")

        # We are authenticated
        self.assertEqual(client.get("/admin/").status_code, 200)

    @patch(
        "authlib.admin_oauth.views.ADMIN_OAUTH_CREATE_USER_CALLBACK",
        new="authlib.admin_oauth.views.create_superuser",
    )
    @patch(
        "authlib.admin_oauth.views.ADMIN_OAUTH_PATTERNS",
        new=[
            (r"^.*@example\.com$", lambda match: match.group(0)),
        ],
    )
    def test_admin_oauth_user_nocreated(self):
        User.objects.create(
            email="user@example.com", password="blabla", is_active=False
        )
        client = Client()
        state = start_oauth(client, "/admin/__oauth__/")
        with google_oauth_data({"email": "user@example.com", "email_verified": True}):
            response = client.get(f"/admin/__oauth__/?code=bla&state={state}")
        # We are not authenticated, inactive user exists
        self.assertRedirects(response, "/admin/login/")

        messages = [str(m) for m in response.wsgi_request._messages]
        self.assertEqual(
            messages, ["No matching staff users for email address 'user@example.com'"]
        )

    @patch(
        "authlib.admin_oauth.views.ADMIN_OAUTH_CREATE_USER_CALLBACK",
        new="authlib.admin_oauth.views.unexisting_method",
    )
    @patch(
        "authlib.admin_oauth.views.ADMIN_OAUTH_PATTERNS",
        new=[
            (r"^.*@example\.com$", lambda match: match.group(0)),
        ],
    )
    def test_admin_oauth_user_create_method_not_imported(self):
        client = Client()
        state = start_oauth(client, "/admin/__oauth__/")
        with (
            google_oauth_data({"email": "user@example.com", "email_verified": True}),
            self.assertRaises(ImportError),
        ):
            client.get(f"/admin/__oauth__/?code=bla&state={state}")

    def test_authlib(self):
        self.assertEqual(
            set(User.objects.values_list("email", flat=True)), {"admin@example.com"}
        )

        client = Client()
        response = client.get("/login/?next=/?keep-this=1")
        for snip in [
            '<label for="id_username">Email:</label>',
            '<a href="/oauth/facebook/">Facebook</a>',
            '<a href="/oauth/google/">Google</a>',
            '<a href="/oauth/twitter/">Twitter</a>',
            '<a href="/oauth/microsoft/">Microsoft</a>',
            '<a href="/email/">Magic link by Email</a>',
        ]:
            self.assertContains(response, snip)

        FacebookOAuth2Client.get_user_data = lambda self: {"email": "test@example.com"}
        response = client.get("/oauth/facebook/?code=bla")
        self.assertRedirects(response, "/?keep-this=1", fetch_redirect_response=False)

        self.assertEqual(
            set(User.objects.values_list("email", flat=True)),
            {"admin@example.com", "test@example.com"},
        )

    def test_invalid_next_cookie(self):
        client = Client()
        response = client.get("/login/?next=http://example.com")
        FacebookOAuth2Client.get_user_data = lambda self: {"email": "test@example.com"}
        response = client.get("/oauth/facebook/?code=bla")
        self.assertRedirects(response, "/?login=1", fetch_redirect_response=False)

    def test_str_and_email_obfuscate(self):
        user = User(email="just-testing@example.com")
        self.assertEqual(user.get_full_name(), "jus***@***.com")
        self.assertEqual(str(user), "jus***@***.com")

    def test_login(self):
        client = Client()
        response = client.post(
            "/login/", {"username": "admin@example.com", "password": "blabla"}
        )
        self.assertRedirects(response, "/?login=1", fetch_redirect_response=False)

    def test_strange_email(self):
        user = User(email="no-email")
        self.assertEqual(user.get_full_name(), "no-***")
        self.assertEqual(str(user), "no-***")


class OAuth2Test(TestCase):
    def test_oauth2_authorization_redirect(self):
        client = Client()

        response = client.get("/oauth/google/")
        self.assertEqual(response.status_code, 302)
        url = urlparse(response["Location"])
        params = dict(parse_qsl(url.query))
        self.assertEqual(params["response_type"], "code")
        self.assertEqual(params["redirect_uri"], "http://testserver/oauth/google/")
        self.assertEqual(params["scope"], "openid email profile")

    def test_oauth2_no_data(self):
        client = Client()

        state = start_oauth(client, "/oauth/google/")
        with google_oauth_data({}):
            response = client.get(f"/oauth/google/?code=bla&state={state}")
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)
        messages = [str(m) for m in response.wsgi_request._messages]
        self.assertEqual(messages, ["Did not get an email address. Please try again."])

    def test_oauth2_success(self):
        client = Client()

        state = start_oauth(client, "/oauth/google/")
        with google_oauth_data({"email": "test3@example.com", "email_verified": True}):
            response = client.get(f"/oauth/google/?code=bla&state={state}")
        self.assertRedirects(response, "/?login=1", fetch_redirect_response=False)
        messages = [str(m) for m in response.wsgi_request._messages]
        self.assertEqual(messages, [])

        self.assertEqual(User.objects.get().email, "test3@example.com")

    def test_oauth2_inactive(self):
        User.objects.create(email="test4@example.com", is_active=False)
        client = Client()

        state = start_oauth(client, "/oauth/google/")
        with google_oauth_data({"email": "test4@example.com", "email_verified": True}):
            response = client.get(f"/oauth/google/?code=bla&state={state}")
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)
        messages = [str(m) for m in response.wsgi_request._messages]
        self.assertEqual(
            messages, ["No active user with email address test4@example.com found."]
        )

    @skipUnless(
        has_login_required_middleware, "LoginRequiredMiddleware needs Django 5.1+"
    )
    @modify_settings(
        MIDDLEWARE={"append": "django.contrib.auth.middleware.LoginRequiredMiddleware"}
    )
    def test_login_not_required(self):
        client = Client()
        response = client.get("/login/")
        self.assertEqual(response.status_code, 200)

        response = client.get("/email/")
        self.assertEqual(response.status_code, 200)


class MicrosoftOAuth2Test(TestCase):
    def _create_request(self, path="/oauth/microsoft/"):
        factory = RequestFactory()
        request = factory.get(path)
        # Bare RequestFactory requests have no session (no middleware runs);
        # the client now needs one to persist/read the OAuth2 CSRF state.
        request.session = SessionStore()
        return request

    def _create_id_token(self, email, name):
        payload = {"preferred_username": email, "name": name, "email": email}
        encoded_payload = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        )
        return f"header.{encoded_payload}.signature"

    def _authorized_client(self, code="test_code"):
        """
        Simulates a full start-then-callback OAuth2 round-trip and returns a
        ``MicrosoftOAuth2Client`` ready for ``get_user_data()``, matching how
        a real browser (and now the state-validating client) behaves.
        """
        start_request = self._create_request("/oauth/microsoft/")
        MicrosoftOAuth2Client(start_request).get_authentication_url()
        state = start_request.session[MICROSOFT_OAUTH_STATE_SESSION_KEY]

        callback_request = self._create_request(
            f"/oauth/microsoft/?code={code}&state={state}"
        )
        callback_request.session = start_request.session
        return MicrosoftOAuth2Client(callback_request)

    def test_microsoft_oauth2_initialization(self):
        request = self._create_request("/fake-path/")
        microsoft_client = MicrosoftOAuth2Client(request, login_hint="user@example.com")
        self.assertEqual(
            microsoft_client.authorization_base_url,
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        )
        self.assertEqual(
            microsoft_client.token_url,
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        )
        self.assertEqual(microsoft_client.scope, ["openid", "profile", "email"])
        self.assertEqual(microsoft_client._login_hint, "user@example.com")

    def test_microsoft_oauth2_authorization_url(self):
        request = self._create_request("/oauth/microsoft/")
        microsoft_client = MicrosoftOAuth2Client(request, login_hint="user@example.com")
        url = microsoft_client.get_authentication_url()
        self.assertIn("login.microsoftonline.com", url)
        self.assertIn("login_hint=user%40example.com", url)
        self.assertIsNotNone(request.session[MICROSOFT_OAUTH_STATE_SESSION_KEY])

    @requests_mock.Mocker()
    def test_microsoft_oauth2_get_user_data_success(self, m):
        id_token = self._create_id_token("test@example.com", "Test User")
        m.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            json={"access_token": "mock_token", "id_token": id_token},
        )

        microsoft_client = self._authorized_client()
        user_data = microsoft_client.get_user_data()
        self.assertEqual(
            user_data, {"email": "test@example.com", "full_name": "Test User"}
        )

    @requests_mock.Mocker()
    def test_microsoft_oauth2_get_user_data_missing_email(self, m):
        id_token = self._create_id_token(None, "Test User")
        m.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            json={"access_token": "mock_token", "id_token": id_token},
        )

        microsoft_client = self._authorized_client()
        user_data = microsoft_client.get_user_data()
        self.assertEqual(user_data, {"email": None, "full_name": "Test User"})

    @requests_mock.Mocker()
    def test_microsoft_oauth2_get_user_data_missing_full_name(self, m):
        id_token = self._create_id_token("test@example.com", None)
        m.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            json={"access_token": "mock_token", "id_token": id_token},
        )

        microsoft_client = self._authorized_client()
        user_data = microsoft_client.get_user_data()
        self.assertEqual(user_data, {"email": "test@example.com", "full_name": None})

    @requests_mock.Mocker()
    def test_microsoft_oauth2_flow_integration(self, m):
        id_token = self._create_id_token("microsoft@example.com", "Microsoft User")
        m.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            json={"access_token": "mock_token", "id_token": id_token},
        )

        client = Client()
        state = start_oauth(client, "/oauth/microsoft/")
        response = client.get(f"/oauth/microsoft/?code=test_code&state={state}")
        self.assertRedirects(response, "/?login=1", fetch_redirect_response=False)
        self.assertEqual(
            User.objects.get(email="microsoft@example.com").email,
            "microsoft@example.com",
        )

    @requests_mock.Mocker()
    def test_microsoft_oauth2_flow_no_email(self, m):
        id_token = self._create_id_token(None, "Microsoft User")
        m.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            json={"access_token": "mock_token", "id_token": id_token},
        )

        client = Client()
        state = start_oauth(client, "/oauth/microsoft/")
        response = client.get(f"/oauth/microsoft/?code=test_code&state={state}")
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)
        messages = [str(msg) for msg in response.wsgi_request._messages]
        self.assertEqual(messages, ["Did not get an email address. Please try again."])

    @requests_mock.Mocker()
    def test_microsoft_oauth2_flow_inactive_user(self, m):
        User.objects.create(email="inactive@example.com", is_active=False)

        id_token = self._create_id_token("inactive@example.com", "Inactive User")
        m.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            json={"access_token": "mock_token", "id_token": id_token},
        )

        client = Client()
        state = start_oauth(client, "/oauth/microsoft/")
        response = client.get(f"/oauth/microsoft/?code=test_code&state={state}")
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)
        messages = [str(msg) for msg in response.wsgi_request._messages]
        self.assertEqual(
            messages,
            ["No active user with email address inactive@example.com found."],
        )

    def test_microsoft_oauth2_authorization_redirect(self):
        client = Client()
        response = client.get("/oauth/microsoft/")
        self.assertEqual(response.status_code, 302)
        url = urlparse(response["Location"])
        params = dict(parse_qsl(url.query))
        self.assertEqual(params["response_type"], "code")
        self.assertEqual(params["redirect_uri"], "http://testserver/oauth/microsoft/")
        self.assertIn("scope", params)

    def test_parse_id_token_exceptions(self):
        request = self._create_request()
        client = MicrosoftOAuth2Client(request)
        self.assertEqual(client._parse_id_token("invalid"), {})
        self.assertEqual(client._parse_id_token(""), {})
        self.assertEqual(client._parse_id_token("a.b"), {})

    def test_is_valid_email_exceptions(self):
        request = self._create_request()
        client = MicrosoftOAuth2Client(request)
        self.assertFalse(client._is_valid_email("invalid"))
        self.assertFalse(client._is_valid_email(""))
        self.assertFalse(client._is_valid_email(None))
        self.assertFalse(client._is_valid_email("not-an-email"))

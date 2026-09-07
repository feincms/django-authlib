from django.conf import settings
from django.test import SimpleTestCase, override_settings

from authlib.admin_oauth.checks import _example_address, check_admin_oauth_patterns
from authlib.checks import check_authentication_backends


class AdminOAuthPatternsCheckTest(SimpleTestCase):
    def check(self, patterns):
        with override_settings(ADMIN_OAUTH_PATTERNS=patterns):
            return check_admin_oauth_patterns(app_configs=None)

    def ids(self, patterns):
        return [message.id for message in self.check(patterns)]

    def test_settings_are_valid(self):
        """The test project's own settings pass."""
        self.assertEqual(check_admin_oauth_patterns(app_configs=None), [])

    def test_valid_patterns(self):
        self.assertEqual(
            self.ids(
                [
                    (r"@example\.com$", "admin@example.com"),
                    (r"^.*@example\.org$", lambda match: match[0]),
                    (r"^(.*@example\.net)$", lambda match: match[1]),
                    # Not matching the whole address is fine as long as the
                    # callable doesn't rely on the matched part.
                    (r"@example\.edu$", lambda match: match.string.lower()),
                    (r"@example\.info$", lambda match: "admin@example.info"),
                ]
            ),
            [],
        )

    def test_match_does_not_cover_the_local_part(self):
        """The trap: the callable only ever gets to see the domain."""
        (message,) = self.check([(r"@example\.com$", lambda match: match[0])])
        self.assertEqual(message.id, "authlib.E004")
        self.assertIn("returned '@example.com'", message.msg)
        self.assertIn("'probe@example.com'", message.msg)

    def test_group_does_not_cover_the_whole_address(self):
        self.assertEqual(
            self.ids([(r"^(.*)@example\.org$", lambda match: match[1])]),
            ["authlib.E004"],
        )

    def test_callable_receives_the_match_not_the_address(self):
        """``lambda email: ...`` is a natural but wrong guess."""
        self.assertEqual(
            self.ids([(r"^.*@example\.org$", lambda email: email.lower())]),
            ["authlib.W001"],
        )

    def test_callable_returning_none(self):
        self.assertEqual(
            self.ids([(r"^.*@example\.org$", lambda match: None)]),
            ["authlib.W002"],
        )

    def test_target_is_not_an_email_address(self):
        self.assertEqual(self.ids([(r"@example\.com$", "admin")]), ["authlib.E004"])

    def test_invalid_regex(self):
        self.assertEqual(
            self.ids([("@example(", "admin@example.com")]), ["authlib.E003"]
        )

    def test_not_a_pair(self):
        self.assertEqual(self.ids(["@example.com"]), ["authlib.E002"])
        self.assertEqual(self.ids([("a", "b", "c")]), ["authlib.E002"])

    def test_not_a_list(self):
        self.assertEqual(self.ids(42), ["authlib.E002"])

    def test_no_patterns_at_all(self):
        with override_settings():
            del settings.ADMIN_OAUTH_PATTERNS
            self.assertEqual(
                [m.id for m in check_admin_oauth_patterns(app_configs=None)],
                ["authlib.E001"],
            )

    def test_patterns_we_cannot_verify_are_left_alone(self):
        """No example address, no output -- guessing would only annoy."""
        self.assertEqual(
            self.ids(
                [
                    # Lookahead
                    (r"^(?!admin)[^@]+@example\.com$", lambda match: match[0]),
                    # Backreference
                    (r"^(.)\1@example\.com$", lambda match: match[0]),
                    # No address can match this one
                    (r"^[^@]+$", lambda match: match[0]),
                ]
            ),
            [],
        )

    def test_example_addresses(self):
        for pattern, expected in [
            (r"@example\.com$", "probe@example.com"),
            (r"^.*@example\.org$", "a@example.org"),
            (r"^[^@]+@example\.org$", "a@example.org"),
            (r"^[a-z]+\.[a-z]+@example\.org$", "a.a@example.org"),
            (r"^user\d+@example\.org$", "user0@example.org"),
            (r"@(example|beispiel)\.ch$", "probe@example.ch"),
            (r"@example\.", "probe@example.com"),
            (r"^\w+@example\.org$", "a@example.org"),
        ]:
            with self.subTest(pattern=pattern):
                self.assertEqual(_example_address(pattern), expected)


class AuthenticationBackendsCheckTest(SimpleTestCase):
    def ids(self, backends):
        with override_settings(AUTHENTICATION_BACKENDS=backends):
            return [m.id for m in check_authentication_backends(app_configs=None)]

    def test_settings_are_valid(self):
        self.assertEqual(check_authentication_backends(app_configs=None), [])

    def test_the_legacy_path_is_reported(self):
        with override_settings(
            AUTHENTICATION_BACKENDS=["authlib.backends.PermissionsBackend"]
        ):
            (message,) = check_authentication_backends(app_configs=None)
        self.assertEqual(message.id, "authlib.E010")
        self.assertIn("RolePermissionsBackend", message.msg)
        self.assertIn("ModelBackend", message.hint)

    def test_the_current_path_is_fine(self):
        self.assertEqual(
            self.ids(
                [
                    "authlib.backends.RolePermissionsBackend",
                    "authlib.backends.EmailBackend",
                ]
            ),
            [],
        )

    def test_projects_without_the_backend(self):
        self.assertEqual(self.ids(["django.contrib.auth.backends.ModelBackend"]), [])

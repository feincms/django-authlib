import re
import time
from urllib.parse import unquote

from django.core import mail
from django.core.exceptions import ValidationError
from django.test import Client, TestCase
from django.test.client import RequestFactory
from django.utils import timezone

from authlib.email import (
    decode,
    get_confirmation_code,
    render_to_mail,
    send_registration_mail,
)
from authlib.little_auth.models import User


def _messages(response):
    return [m.message for m in response.context["messages"]]


class RegistrationTest(TestCase):
    def test_registration(self):
        client = Client()
        response = client.get("/email/")

        response = client.post("/email/", {"email": "test@example.com"})
        self.assertRedirects(response, "/email/")
        response = client.get("/email/")
        self.assertEqual(_messages(response), ["Please check your mailbox."])

        self.assertEqual(len(mail.outbox), 1)
        body = mail.outbox[0].body
        url = unquote([line for line in body.splitlines() if "testserver" in line][0])

        self.assertTrue("http://testserver/email/dGVzdEBleGFtcGxlLmNvbTo:" in url)

        response = client.get(url)
        self.assertRedirects(response, "/?login=1", fetch_redirect_response=False)

        response = client.post("/email/", {"email": "test2@example.com"})
        self.assertContains(response, "does not match the email of the account you")

        response = client.get("/logout/")
        self.assertRedirects(response, "/login/")  # The default.

        # Set user to inactive
        User.objects.all().update(is_active=False)
        client = Client()
        response = client.get(url)

        response = client.get(url)
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)
        response = client.get("/login/")
        self.assertContains(
            response, "No active user with email address test@example.com found."
        )

    def test_existing_user(self):
        user = User.objects.create(email="test@example.com")

        request = RequestFactory().get("/")
        send_registration_mail("test@example.com", request=request)

        self.assertEqual(len(mail.outbox), 1)
        body = mail.outbox[0].body
        url = unquote([line for line in body.splitlines() if "testserver" in line][0])

        self.assertTrue(
            re.match(r"http://testserver/email/dGVzdEBleGFtcGxlLmNvbTo:", url)
        )

        response = self.client.get(url)

        self.assertRedirects(response, "/?login=1", fetch_redirect_response=False)

        user = User.objects.get()
        self.assertEqual(user.email, "test@example.com")

        user.last_login = timezone.now()
        user.save()

        response = self.client.get(url.replace("dGVz", "dGVa", 1), follow=True)
        self.assertEqual(
            _messages(response),
            ["Unable to verify the signature. Please request a new registration link."],
        )

        user.delete()
        response = self.client.get(url, follow=True)
        self.assertEqual(
            _messages(response),
            ["Unable to verify the signature. Please request a new registration link."],
        )

    def test_empty_render_to_mail(self):
        mail = render_to_mail("empty", {})
        self.assertEqual(mail.subject, "")

    def test_payload(self):
        self.client.post("/custom/", {"email": "test42@example.com"})

        self.assertEqual(len(mail.outbox), 1)
        body = mail.outbox[0].body
        url = unquote([line for line in body.splitlines() if "testserver" in line][0])

        response = self.client.get(url)
        self.assertEqual(
            response.content, b"email:test42@example.com payload:hello:world:42"
        )

    def test_expiry(self):
        code = get_confirmation_code("test@example.com")
        self.assertTrue(code.startswith("dGVzdEBleGFtcGxlLmNvbTo:"))

        self.assertEqual(decode(code, max_age=5), ["test@example.com", ""])

        with self.assertRaises(ValidationError) as cm:
            time.sleep(2)
            decode(code, max_age=1)

        self.assertEqual(
            cm.exception.messages,
            ["The link is expired. Please request another registration link."],
        )

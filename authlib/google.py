import base64
import json
import os

from django.conf import settings
from requests_oauthlib import OAuth2Session


def b64decode(input):
    if isinstance(input, str):
        input = input.encode("ascii")

    rem = len(input) % 4

    if rem > 0:
        input += b"=" * (4 - rem)

    return base64.urlsafe_b64decode(input)


class GoogleOAuth2Client:
    authorization_base_url = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url = "https://www.googleapis.com/oauth2/v4/token"
    scope = ["openid", "email", "profile"]
    client_id = getattr(settings, "GOOGLE_CLIENT_ID", None)
    client_secret = getattr(settings, "GOOGLE_CLIENT_SECRET", None)

    def __init__(self, request, *, login_hint=None, authorization_params=None):
        # let oauthlib be less strict on scope mismatch
        os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

        self._request = request
        self._session = OAuth2Session(
            self.client_id,
            scope=self.scope,
            redirect_uri=request.build_absolute_uri("."),
        )
        self._login_hint = login_hint
        self._authorization_params = authorization_params or {}

    def get_authentication_url(self):
        self._authorization_params.setdefault("login_hint", self._login_hint)
        authorization_url, self._state = self._session.authorization_url(
            self.authorization_base_url, **self._authorization_params
        )

        return authorization_url

    def get_user_data(self):
        token = self._session.fetch_token(
            self.token_url,
            client_secret=self.client_secret,
            authorization_response=self._request.build_absolute_uri(
                self._request.get_full_path()
            ),
        )
        # NOTE! We received the id_token directly from Google. Skipping
        # verification is fine in this case but you MUST NOT SAVE AND USE THIS
        # TOKEN LATER.
        data = json.loads(b64decode(token["id_token"].split(".")[1]).decode("utf-8"))
        return (
            {"email": data.get("email"), "full_name": data.get("name")}
            if data.get("email_verified")
            else {}
        )

import base64
import json
import os

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from requests_oauthlib import OAuth2Session


class MicrosoftOAuth2Client:
    """Microsoft OAuth2 client for django-authlib.

    Requires OAUTHLIB_RELAX_TOKEN_SCOPE=1 to handle scope mismatches.
    """

    authorization_base_url = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    )
    token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    scope = ["openid", "profile", "email"]
    client_id = getattr(settings, "MICROSOFT_CLIENT_ID", None)
    client_secret = getattr(settings, "MICROSOFT_CLIENT_SECRET", None)
    prompt = "select_account"

    def __init__(self, request, *, login_hint=None, authorization_params=None):
        # Relax scope validation for Microsoft OAuth2 (required for their flow)
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

    def _parse_id_token(self, id_token):
        try:
            payload = id_token.split(".")[1]
            payload += "=" * (4 - len(payload) % 4)
            return json.loads(base64.urlsafe_b64decode(payload))
        except (IndexError, ValueError):
            return {}

    def _is_valid_email(self, value):
        if not value:
            return False
        try:
            validate_email(value)
            return True
        except ValidationError:
            return False

    def get_user_data(self):
        self._session.fetch_token(
            self.token_url,
            client_secret=self.client_secret,
            authorization_response=self._request.build_absolute_uri(
                self._request.get_full_path()
            ),
        )
        token = self._session.token
        id_token = token.get("id_token")
        claims = self._parse_id_token(id_token) if id_token else {}

        preferred_username = claims.get("preferred_username")
        email = claims.get("email")
        user_email = (
            preferred_username if self._is_valid_email(preferred_username) else email
        )

        return {
            "email": user_email,
            "full_name": claims.get("name"),
        }

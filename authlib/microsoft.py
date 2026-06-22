import os

from django.conf import settings
from requests_oauthlib import OAuth2Session


class MicrosoftOAuth2Client:
    authorization_base_url = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    )
    token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    scope = ["https://graph.microsoft.com/User.Read"]
    client_id = settings.MICROSOFT_CLIENT_ID
    client_secret = settings.MICROSOFT_CLIENT_SECRET

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
        self._session.fetch_token(
            self.token_url,
            client_secret=self.client_secret,
            authorization_response=self._request.build_absolute_uri(
                self._request.get_full_path()
            ),
        )
        data = self._session.get(
            "https://graph.microsoft.com/v1.0/me",
        ).json()

        print(data)

        return {"email": data.get("mail"), "full_name": data.get("displayName")}

from django.conf import settings
from requests_oauthlib import OAuth2Session


FACEBOOK_OAUTH_STATE_SESSION_KEY = "facebook-oauth-state"


class FacebookOAuth2Client:
    authorization_base_url = "https://www.facebook.com/dialog/oauth"
    token_url = "https://graph.facebook.com/oauth/access_token"
    scope = ["email"]
    client_id = settings.FACEBOOK_CLIENT_ID
    client_secret = settings.FACEBOOK_CLIENT_SECRET

    def __init__(self, request):
        self._request = request
        # Popped (not just read) so that a state value can only ever be
        # used to validate a single callback.
        self._state = request.session.pop(FACEBOOK_OAUTH_STATE_SESSION_KEY, None)
        self._session = OAuth2Session(
            self.client_id,
            scope=self.scope,
            redirect_uri=request.build_absolute_uri("."),
            state=self._state,
        )

    def get_authentication_url(self):
        authorization_url, state = self._session.authorization_url(
            self.authorization_base_url,
            access_type="online",  # Only right now.
            # approval_prompt='force',  # Maybe not, later.
        )
        self._request.session[FACEBOOK_OAUTH_STATE_SESSION_KEY] = state

        return authorization_url

    def get_user_data(self):
        if not self._state:
            # No (or an already consumed) authorization request is pending
            # for this session -- refuse to proceed instead of silently
            # skipping CSRF state validation.
            raise ValueError("No pending OAuth2 authorization request found.")

        self._session.fetch_token(
            self.token_url,
            client_secret=self.client_secret,
            authorization_response=self._request.build_absolute_uri(
                self._request.get_full_path()
            ),
        )
        data = self._session.get(
            "https://graph.facebook.com/me", params={"fields": "email,name"}
        ).json()

        return {"email": data.get("email"), "full_name": data.get("name")}

from django.conf import settings
from social_core.backends.oauth import BaseOAuth2
import json
from typing import TYPE_CHECKING, Any, Literal
if TYPE_CHECKING:
    from collections.abc import Mapping

    from requests.auth import AuthBase

import logging
logger = logging.getLogger(__name__)


class HTOAuth2(BaseOAuth2):
    name = "HT"
    ID_KEY = "username"
    ACCESS_TOKEN_METHOD = "POST"
    DEFAULT_SCOPE = ["openid", "email", "profile"]
    EXTRA_DATA = [("id_token", "id_token")]  # no session_state here!
    REDIRECT_STATE = False
    
    def authorization_url(self):
        return settings.SOCIAL_AUTH_HT_AUTHORIZATION_URL

    def access_token_url(self):
        return settings.SOCIAL_AUTH_HT_ACCESS_TOKEN_URL

    def user_data_url(self):
        return settings.SOCIAL_AUTH_HT_USER_DATA_URL
    

    def auth_params(self, state=None):
        """
        Return parameters used in the authorization URL.
        Here you can remap or add custom parameters before sending to the IdP.
        """
        params = super().auth_params(state)
        
        # Example: remap 'scope' to 'custom_scope' or add extra params
        if "state" in params:
            params["redirect"] = params.pop("state")

        if "redirect_uri" in params:
            params["backlink"] = params.pop("redirect_uri")

        return params

    def auth_complete(self, *args, **kwargs):
        """
        Override to prevent KeyError when session_state is missing.
        """
        logger.info("HTOAuth2.auth_complete called, data=%s", self.data)
        data = self.data.copy()
        # Some IdPs (non-Keycloak) don't include session_state
        if "session_state" not in data:
            data["session_state"] = None

        if "authorization_code" in data:
            data["code"] = data["authorization_code"]

        if "redirect" in data:
            data["state"] = data["redirect"]
    
        self.data = data
        return super().auth_complete(*args, **kwargs)
    

    def request_access_token(
        self,
        url: str,
        method: Literal["GET", "POST", "DELETE"] = "GET",
        headers: Mapping[str, str | bytes] | None = None,
        data: dict | bytes | str | None = None,
        auth: tuple[str, str] | AuthBase | None = None,
        params: dict | None = None,
    ):
        logger.info("request_access_token")
        """
        Custom token exchange for HT IdP.
        Sends JSON with authorization_code and extracts user info directly from the response.
        """
        code = self.data.get("authorization_code") or self.data.get("code")
        if not code:
            raise ValueError("No authorization code available for token exchange")

        client_id, client_secret = self.get_key_and_secret()
        payload = {
            "authorization_code": code,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        headers = {"Content-Type": "application/json"}

        resp = self.request(
            self.access_token_url(), method="POST",
            data=json.dumps(payload), headers=headers
        )

        logger.info("HT token exchange response: %s %s", resp.status_code, resp.text[:500])

        try:
            body = resp.json()
        except Exception:
            body = json.loads(resp.text or "{}")

        # Extract user + token info
        d = body.get("data") or {}
        user_data = d.get("data") or {}
        token = d.get("token")

        if not token:
            raise Exception(f"Couldn't extract access token from response: {body!r}")

        # Merge token and user info so PSA can reuse it
        merged = {
            "access_token": token,
            "contact_id": d.get("contact_id"),
            "username": d.get("username"),
            "fullname": user_data.get("ho_ten"),
            "email": user_data.get("email"),
            "avatar": user_data.get("avatar"),
        }

        return merged

    def user_data(self, access_token, *args, **kwargs):
        """
        IdP already returned user data in the token response.
        PSA will call this after `request_access_token`, so we just reuse it.
        """
        # Reuse data returned from request_access_token
        return getattr(self, "access_token_data", {})

    def get_user_details(self, response):
        return {
            "username": response.get("username"),
            "email": response.get("email"),
            "fullname": response.get("fullname"),
            "first_name": "",
            "last_name": "",
        }

    def get_user_id(self, details, response):
        return details.get(self.ID_KEY)
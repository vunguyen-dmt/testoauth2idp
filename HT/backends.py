from django.conf import settings
from social_core.backends.oauth import BaseOAuth2

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

    def auth_complete(self, *args, **kwargs):
        """
        Override to prevent KeyError when session_state is missing.
        """
        data = self.data.copy()
        # Some IdPs (non-Keycloak) don't include session_state
        if "session_state" not in data:
            data["session_state"] = None
        self.data = data
        return super().auth_complete(*args, **kwargs)

    def get_user_details(self, response):
        return {
            "username": response.get("preferred_username") or response.get("sub"),
            "email": response.get("email"),
            "fullname": response.get("name"),
            "first_name": response.get("given_name", ""),
            "last_name": response.get("family_name", ""),
        }

    def user_data(self, access_token, *args, **kwargs):
        return self.get_json(
            self.user_data_url(),
            headers={"Authorization": f"Bearer {access_token}"}
        )

    def get_user_id(self, details, response):
        return details.get(self.ID_KEY)

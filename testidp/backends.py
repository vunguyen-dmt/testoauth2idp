from django.conf import settings
from social_core.backends.oauth import BaseOAuth2

class TestIdPOAuth2(BaseOAuth2):
    name = "testidp"  # appears in URLs: /auth/login/myidp/

    AUTHORIZATION_URL = settings.SOCIAL_AUTH_TESTIDP_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = settings.SOCIAL_AUTH_TESTIDP_ACCESS_TOKEN_URL
    USER_DATA_URL = settings.SOCIAL_AUTH_TESTIDP_USER_DATA_URL

    DEFAULT_SCOPE = ["openid", "email", "profile"]

    def get_user_details(self, response):
        """Map IdP JSON response to Open edX fields."""
        return {
            "username": response.get("preferred_username") or response.get("sub"),
            "email": response.get("email"),
            "fullname": response.get("name"),
            "first_name": response.get("given_name", ""),
            "last_name": response.get("family_name", ""),
        }

    def user_data(self, access_token, *args, **kwargs):
        """Fetch user profile from IdP using access token."""
        return self.get_json(
            self.USER_DATA_URL,
            headers={"Authorization": f"Bearer {access_token}"}
        )

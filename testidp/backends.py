from django.conf import settings
from social_core.backends.oauth import BaseOAuth2

class TestIdPOAuth2(BaseOAuth2):
    name = "testidp"  # will show up as /auth/login/testidp/

    DEFAULT_SCOPE = ["openid", "email", "profile"]

    def authorization_url(self):
        return settings.SOCIAL_AUTH_TESTIDP_AUTHORIZATION_URL

    def access_token_url(self):
        return settings.SOCIAL_AUTH_TESTIDP_ACCESS_TOKEN_URL

    def user_data_url(self):
        return settings.SOCIAL_AUTH_TESTIDP_USER_DATA_URL

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
            self.user_data_url(),
            headers={"Authorization": f"Bearer {access_token}"}
        )

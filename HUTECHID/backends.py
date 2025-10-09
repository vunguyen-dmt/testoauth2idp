from django.conf import settings
from social_core.backends.oauth import BaseOAuth2
from social_django.models import UserSocialAuth
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Q
from common.djangoapps.student.models import UserProfile
import json
import secrets
import string
import logging

logger = logging.getLogger(__name__)


class HUTECHIDOAuth2(BaseOAuth2):
    name = "HUTECHID"
    ID_KEY = "username"
    ACCESS_TOKEN_METHOD = "POST"
    DEFAULT_SCOPE = ["openid", "email", "profile"]
    EXTRA_DATA = []
    REDIRECT_STATE = False

    def authorization_url(self):
        return settings.SOCIAL_AUTH_HUTECHID_AUTHORIZATION_URL

    def access_token_url(self):
        return settings.SOCIAL_AUTH_HUTECHID_ACCESS_TOKEN_URL

    def get_client_id(self):
        return settings.SOCIAL_AUTH_HUTECHID_KEY

    def get_client_secret(self):
        return settings.SOCIAL_AUTH_HUTECHID_SECRET

    def auto_create_user_enabled(self):
        return getattr(settings, "SOCIAL_AUTH_HUTECHID_AUTO_CREATE_USER_ENABLE", False)

    def auth_params(self, state=None):
        params = super().auth_params(state)
        if "state" in params:
            params["redirect"] = params.pop("state")
        if "redirect_uri" in params:
            params["backlink"] = params.pop("redirect_uri")
        return params

    def auth_complete(self, *args, **kwargs):
        data = self.data.copy()
        data.setdefault("session_state", None)
        if "authorization_code" in data:
            data["code"] = data["authorization_code"]
        if "redirect" in data:
            data["state"] = data["redirect"]
        self.data = data
        return super().auth_complete(*args, **kwargs)

    def request_access_token(self, url, method, headers, data, auth, params):
        code = self.data.get("authorization_code") or self.data.get("code")
        if not code:
            raise ValueError("No authorization code available for token exchange")

        payload = {
            "authorization_code": code,
            "client_id": self.get_client_id(),
            "client_secret": self.get_client_secret(),
        }
        headers = {"Content-Type": "application/json"}

        resp = self.request(
            self.access_token_url(),
            method="POST",
            data=json.dumps(payload),
            headers=headers,
        )

        try:
            body = resp.json()
        except Exception:
            body = json.loads(resp.text or "{}")

        d = body.get("data") or {}
        user_data = d.get("data") or {}
        token = d.get("token")

        if not token:
            logger.error(f"Couldn't extract access token from response: {body!r}")
            raise Exception(f"Couldn't extract access token from response: {body!r}")


        username = (d.get("username") or "").strip()
        email = (user_data.get("email") or "").strip()
        fullname = (user_data.get("ho_ten") or "").strip()
        # generate a unique temporary email so user can be created.
        if not email:
            email = self.generate_temp_email('hutech.edu.vn', 32)

        # set a default fullname.
        if not fullname:
            fullname = username

        merged = {
            "access_token": token,
            "username": username,
            "fullname": fullname,
            "email": email,
        }

        self.access_token_data = merged

        if self.auto_create_user_enabled():
            self.ensure_user_linked(merged)

        return merged

    def ensure_user_linked(self, merged):
        username = (merged.get("username") or "").strip()
        email = (merged.get("email") or "").strip()
        fullname = (merged.get("fullname") or "").strip()

        User = get_user_model()

        if not username and not email:
            logger.warning("Cannot create/link user — both username and email missing.")
            return None

        with transaction.atomic():
            linked = UserSocialAuth.objects.filter(provider=self.name, uid=username).first()
            if linked:
                return linked.user

            # Find existing user by username or email
            user = User.objects.filter(
                Q(username=username)
                | Q(email=email)
                | Q(username=email)
                | Q(email=username)
            ).first()

            if not user:
                # Create new user
                password = self.generate_strong_password(32)
                try:
                    user = User.objects.create_user(username=username, email=email, password = password)
                    UserProfile.objects.create(user=user, name=fullname)
                    logger.info(f"Created new user {username} for {self.name} IdP")
                except Exception as e:
                    logger.exception(f"Failed to create user for {username}: {e}")
                    raise
            else:
                logger.info(f"Linking existing user {user.username} to {self.name}")

            # Link social auth
            # case: same email but different username, can not log this user in, require a manual data change.
            if user and user.username == username:
                UserSocialAuth.objects.get_or_create(user=user, provider=self.name, uid=username)

            # update user data
            profile, _ = UserProfile.objects.get_or_create(user=user)
            if fullname and profile.name != fullname:
                profile.name = fullname
                profile.save(update_fields=["name"])

            return user

    def user_data(self, access_token, *args, **kwargs):
        return getattr(self, "access_token_data", {}).copy()

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
    
    def generate_strong_password(self, length: int = 32) -> str:
        """Generate a secure random password with letters, digits, and symbols."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def generate_temp_email(self, domain="hutech.edu.vn", length=32):
        alphabet = string.ascii_letters + string.digits
        random_part = ''.join(secrets.choice(alphabet) for _ in range(length))
        return f"{random_part}-temp-email@{domain}"
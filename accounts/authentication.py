# accounts/authentication.py
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from .utils import decode_token  # your renamed helpers
from .models import User

class SimpleBearerAccessTokenAuthentication(BaseAuthentication):
    """
    Reads Authorization: Bearer <access_jwt> and authenticates the user.
    Expects 'type' == 'access' inside the token.
    """
    keyword = b"bearer"

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != self.keyword:
            return None  # no auth header; let other authenticators run / or IsAuthenticated will fail

        if len(auth) == 1:
            raise AuthenticationFailed("Invalid Authorization header")
        if len(auth) > 2:
            raise AuthenticationFailed("Invalid Authorization header")

        token = auth[1].decode("utf-8")
        try:
            payload = decode_token(token, verify_exp=True)
        except Exception:
            raise AuthenticationFailed("Invalid or expired access token")

        if payload.get("type") != "access":
            raise AuthenticationFailed("Wrong token type")

        user_id = payload.get("user_id")
        try:
            user = User.objects.get(uid=user_id)  # adjust if you use a different id field
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")

        # Attach payload if you want later
        request.jwt_payload = payload
        return (user, payload)

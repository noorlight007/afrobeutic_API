import jwt
from django.conf import settings
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from django.conf import settings


JWT_SECRET = getattr(settings, "JWT_SECRET", settings.SECRET_KEY)
JWT_ALGORITHM = getattr(settings, "JWT_ALGORITHM", "HS256")

def generate_access_token(user):
    payload = {
        'type': 'access',
        'user_id': str(user.uid),
        'email': user.email,
        "is_platform_admin": bool(getattr(user, "is_platform_admin", False)),
        "is_platform_staff": bool(getattr(user, "is_platform_staff", False)),
        'exp': datetime.now(timezone.utc) + settings.JWT_ACCESS_EXP,
        'iat': datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def generate_refresh_token(user):
    payload = {
        'user_id': str(user.uid),
        'type': 'refresh',
        'exp': datetime.now(timezone.utc) + settings.JWT_REFRESH_EXP,
        'iat': datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def decode_token(token: str, verify_exp: bool = True) -> Dict[str, Any]:
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
        options={"verify_exp": verify_exp},
    )
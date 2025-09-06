import jwt
from django.conf import settings
from datetime import datetime, timedelta, timezone

def generate_access_token(user, account_id = None):
    payload = {
        'user_id': str(user.uid),
        'account_id': account_id if account_id else None,
        'email': user.email,
        'type': 'access',
        'exp': datetime.now(timezone.utc) + settings.JWT_ACCESS_EXP,
        'iat': datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def generate_refresh_token(user, account_id = None):
    payload = {
        'user_id': str(user.uid),
        'account_id': account_id if account_id else None,
        'type': 'refresh',
        'exp': datetime.now(timezone.utc) + settings.JWT_REFRESH_EXP,
        'iat': datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

# accounts/views_token.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.throttling import ScopedRateThrottle

# drf-spectacular
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample, inline_serializer
from rest_framework import serializers as drf_serializers

from django.conf import settings
import jwt

from .utils import generate_access_token, decode_token
from .models import User
from rest_framework.permissions import AllowAny


class RefreshTokenView(APIView):
    throttle_scope = 'refresh_token'
    throttle_classes = [ScopedRateThrottle]
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        operation_id="auth_refresh",
        tags=["Auth", "Admins - Auth"],
        summary="Access Token generation",
        description="Refresh the access token using a valid refresh token.",
        request=inline_serializer(
            name="RefreshTokenRequest",
            fields={"refresh_token": drf_serializers.CharField()},
        ),
        examples=[
            OpenApiExample(
                "RefreshTokenRequestExample",
                value={"refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi..."},
                request_only=True,
            )
        ],
        responses={
            200: OpenApiResponse(
                response=inline_serializer(
                    name="RefreshTokenSuccess",
                    fields={"access_token": drf_serializers.CharField(required = False)},
                ),
                description="Access token refreshed successfully",
                examples=[OpenApiExample(
                    "Success",
                    value={"access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi..."}
                )],
            ),
            401: OpenApiResponse(
                response=inline_serializer(
                    name="RefreshTokenError",
                    fields={"detail": drf_serializers.CharField(required = False)},
                ),
                description="Invalid or expired refresh token",
                examples=[OpenApiExample(
                    "Expired",
                    value={"detail": "Refresh token expired"}
                )],
            ),
        },
    )
    def post(self, request):
        token = request.data.get('refresh_token')
        if not token:
            raise AuthenticationFailed("Refresh token required")

        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
            if payload.get('type') != 'refresh':
                raise AuthenticationFailed("Invalid token type")
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Refresh token expired")
        except jwt.DecodeError:
            raise AuthenticationFailed("Invalid token")

        user_id = payload.get('user_id')
        try:
            # Your project uses a UUID field 'uid' — adjust if needed
            user = User.objects.get(uid=user_id)
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")

        new_access = generate_access_token(user)
        return Response({'access_token': new_access}, status=status.HTTP_200_OK)


class TokenVerifyView(APIView):
    """
    Minimal verification endpoint — validates signature & expiry.
    """
    throttle_scope = 'refresh_token'  # reuse or define a separate scope
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        operation_id="auth_token_verify",
        tags=["Auth", "Admins - Auth"],
        summary="Verify a token (access/refresh)",
        request=inline_serializer(
            name="TokenVerifyRequest",
            fields={"token": drf_serializers.CharField()},
        ),
        responses={
            200: OpenApiResponse(
                response=inline_serializer(
                    name="TokenVerifyOK",
                    fields={
                        "valid": drf_serializers.BooleanField(required = False),
                        "type": drf_serializers.CharField(required = False),
                        "user_id": drf_serializers.CharField(required = False),
                        "email": drf_serializers.EmailField(help_text= "for Access Token only",default = "None"),
                        "is_platform_admin": drf_serializers.CharField(help_text= "for Access Token only",default = "None"),
                        "is_platform_staff": drf_serializers.CharField(help_text= "for Access Token only",default = "None"),
                        "exp": drf_serializers.IntegerField(required = False),
                    },
                ),
                description="Valid token",
            ),
            400: OpenApiResponse(
                response=inline_serializer(
                    name="TokenVerifyError",
                    fields={"detail": drf_serializers.CharField(required = False)},
                ),
                description="Invalid token",
            ),
        },
    )
    def post(self, request):
        token = request.data.get('token')
        if not token:
            return Response({"detail": "token is required"}, status=400)
        try:
            payload = decode_token(token, verify_exp=True)
        except Exception:
            return Response({"detail": "Invalid or expired token"}, status=400)
        
        # payload = {
        #     'type': 'access',
        #     'user_id': str(user.uid),
        #     'email': user.email,
        #     "is_platform_admin": bool(getattr(user, "is_platform_admin", False)),
        #     "is_platform_staff": bool(getattr(user, "is_platform_staff", False)),
        #     'exp': datetime.now(timezone.utc) + settings.JWT_ACCESS_EXP,
        #     'iat': datetime.now(timezone.utc),
        # }
        return Response({
            "valid": True,
            "type": payload.get("type"),
            "user_id": payload.get("user_id"),
            "email": payload.get("email") if payload.get("type") == "access" else None,
            "is_platform_admin": payload.get("is_platform_admin") if payload.get("type") == "access" else None,
            "is_platform_staff": payload.get("is_platform_staff") if payload.get("type") == "access" else None,
            "exp": payload.get("exp"),
        }, status=200)

# accounts/views.py
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.throttling import ScopedRateThrottle

from .models import TempUser, User, Account, AccountUser
from .serializers import UserRegisterSerializer, VerifySerializer
from .email_sender import send_verification_email

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework import status

def country_to_tz(country: str | None) -> str:
    if not country:
        return "UTC"
    return {
        'united states': 'America/New_York',
        'bangladesh': 'Asia/Dhaka',
        'india': 'Asia/Kolkata',
        'france': 'Europe/Paris',
        'germany': 'Europe/Berlin',
    }.get(country.strip().lower(), "UTC")

# Parameter/response schemas
register_success_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        "message": openapi.Schema(type=openapi.TYPE_STRING, example="Verification email sent."),
        "expires_in_minutes": openapi.Schema(type=openapi.TYPE_INTEGER, example=60),
    },
)

register_validation_error_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    additional_properties=openapi.Schema(type=openapi.TYPE_STRING),
    example={"email": "email is not valid", "password": "Password must be at least 8 characters"}
)

rate_limited_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        "detail": openapi.Schema(type=openapi.TYPE_STRING, example="Request was throttled. Expected available in 3600 seconds.")
    },
)


class RegisterView(APIView):
    throttle_scope = 'register'
    throttle_classes = [ScopedRateThrottle]

    @swagger_auto_schema(
        operation_id="auth_register",
        operation_summary="User Registration (email verification flow)",
        operation_description=(
            "Creates a temporary registration record and emails a verification link. "
            "No real user/account is created until the link is clicked."
        ),
        request_body=UserRegisterSerializer,
        responses={
            status.HTTP_201_CREATED: openapi.Response("Verification email sent", register_success_schema),
            status.HTTP_400_BAD_REQUEST: openapi.Response("Validation error", register_validation_error_schema),
            status.HTTP_429_TOO_MANY_REQUESTS: openapi.Response("Rate limited", rate_limited_schema),
        },
        tags=["Auth"],
    )

    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data, context={"ttl_minutes": settings.TOKEN_TTL_MINUTES})
        serializer.is_valid(raise_exception=True)
        temp_user = serializer.save()
        send_verification_email(temp_user)
        return Response(
            {"message": "Verification email sent.", "expires_in_minutes": settings.TOKEN_TTL_MINUTES},
            status=status.HTTP_201_CREATED
        )
    

class VerifyView(APIView):
    def get(self, request):
        serializer = VerifySerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]

        # Lock the temp row to avoid double consumption
        with transaction.atomic():
            try:
                tmp = TempUser.objects.select_for_update().get(verification_token=token, is_used=False)
            except TempUser.DoesNotExist:
                return Response({"detail": "Invalid or already used token."}, status=status.HTTP_400_BAD_REQUEST)

            if tmp.token_expires_at < timezone.now():
                return Response({"detail": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST)

            # Create permanent User + Account + AccountUser
            tz = country_to_tz(tmp.country)
            user = User.objects.create(
                first_name=tmp.first_name,
                last_name=tmp.last_name,
                email=tmp.email.lower(),
                password=tmp.password_hash,  # already hashed
                timezone=tz,
            )
            account = Account.objects.create(name=tmp.account_name or f"{tmp.first_name}'s Account")
            AccountUser.objects.create(account=account, user=user, role="owner", is_active=True)

            # mark used + delete the temp row (your requirement)
            tmp.is_used = True
            tmp.save(update_fields=["is_used", "updated_at"])
            tmp.delete()  # hard delete

        return Response(
            {"message": "Email verified. Your account has been created.", "user_id": str(user.uid), "account_id": str(account.id)},
            status=status.HTTP_200_OK
        )

# accounts/views.py
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.db.models import Q

from .models import TempUser, User, Account, AccountUser, TempAdmin
from billing.models import Plan, Subscription
from .serializers import (
    UserRegisterSerializer, AdminRegisterSerializer, VerifySerializer,
    AccountListItemSerializer, PaginatedAccountResponseSerializer,
    LoginSerializer
)
from .email_sender import send_verification_email

# --- drf-spectacular imports (replace drf_yasg) ------------------------------
from drf_spectacular.utils import (
    OpenApiExample,
    extend_schema,
    OpenApiParameter,
    OpenApiResponse,
    OpenApiTypes,
    inline_serializer,
)
from accounts.permissions import (
    IsPlatformAdminOrStaff,
    IsPlatformAdminOnly,
    IsAccountOwner,
    IsAccountOwnerOrAdmin,
    IsAccountOwnerAdminOrStaff,
)
from rest_framework import serializers as drf_serializers
# ---------------------------------------------------------------------------

from datetime import timedelta


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


# accounts/views.py (add this helper near the top or in a services module)
def create_starter_trial(account):
    """
    Creates a 30-day trial Subscription on the Starter plan starting now.
    If the plan doesn't exist (seed not run), it will raise DoesNotExist.
    """
    plan = Plan.objects.get(code="starter", is_active=True)
    now = timezone.now()
    return Subscription.objects.create(
        account=account,
        plan=plan,
        status="trialing",
        current_period_start=now,
        current_period_end=now + timedelta(days=30),  # anchor first cycle
        trial_ends_at=now + timedelta(days=30),
    )


# -------------------- Response schemas (inline serializers) -------------------
register_success_schema = inline_serializer(
    name="RegisterSuccess",
    fields={
        "message": drf_serializers.CharField(default="Verification email sent."),
        "expires_in_minutes": drf_serializers.IntegerField(default=60),
    },
)

register_validation_error_schema = inline_serializer(
    name="RegisterValidationError",
    fields={
        # key = field name, value = error message
        # (example only; actual keys may vary)
        # Use Dict[str, str] for a simple field->error map
        "__root__": drf_serializers.DictField(
            child=drf_serializers.CharField(required = False),
            help_text="Field-wise validation errors"
        )
    }
)

rate_limited_schema = inline_serializer(
    name="RateLimitedError",
    fields={
        "detail": drf_serializers.CharField(
            default="Request was throttled. Expected available in 3600 seconds."
        )
    }
)
# -----------------------------------------------------------------------------


class RegisterView(APIView):
    throttle_scope = 'register'
    throttle_classes = [ScopedRateThrottle]
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        auth=[],
        operation_id="auth_register",
        summary="User Registration",
        description=(
            "Creates a temporary registration record and emails a verification link. "
            "No real user/account is created until the link is clicked."
        ),
        request=UserRegisterSerializer,
        responses={
            status.HTTP_201_CREATED: OpenApiResponse(
                response=register_success_schema,
                description="Verification email sent"
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=register_validation_error_schema,
                description="Validation error"
            ),
            status.HTTP_429_TOO_MANY_REQUESTS: OpenApiResponse(
                response=rate_limited_schema,
                description="Rate limited"
            ),
        },
        tags=["Registration"],
    )
    def post(self, request):
        with transaction.atomic():
            serializer = UserRegisterSerializer(
                data=request.data,
                context={"ttl_minutes": settings.TOKEN_TTL_MINUTES}
            )
            serializer.is_valid(raise_exception=True)
            temp_user = serializer.save()
            send_verification_email(temp_user)
            return Response(
                {"message": "Verification email sent.",
                 "expires_in_minutes": settings.TOKEN_TTL_MINUTES},
                status=status.HTTP_201_CREATED
            )

### Admin Registration
class AdminRegisterView(APIView):
    throttle_scope = 'register'
    throttle_classes = [ScopedRateThrottle]
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        auth=[],
        operation_id="auth_register",
        summary="Admin Registration",
        description=(
            "Creates a temporary registration record and emails a verification link. "
            "No real user/account is created until the link is clicked."
        ),
        request=AdminRegisterSerializer,
        responses={
            status.HTTP_201_CREATED: OpenApiResponse(
                response=register_success_schema,
                description="Verification email sent"
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=register_validation_error_schema,
                description="Validation error"
            ),
            status.HTTP_429_TOO_MANY_REQUESTS: OpenApiResponse(
                response=rate_limited_schema,
                description="Rate limited"
            ),
        },
        tags=["Registration"],
    )
    def post(self, request):
        if not request.data['is_platform_admin'] or not request.data['is_platform_staff']:
            return Response(
                {"message": "Role must be selected for platform admin"},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not request.data['is_platform_admin'].lower() in ['true','false'] and not request.data['is_platform_staff'].lower() in ['true','false']:
            return Response(
                {"message": "Role must be selected for platform admin"},
                status=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():
            serializer = AdminRegisterSerializer(
                data=request.data,
                context={"ttl_minutes": settings.TOKEN_TTL_MINUTES}
            )
            serializer.is_valid(raise_exception=True)
            temp_user = serializer.save()
            send_verification_email(temp_user, True)
            return Response(
                {"message": "Verification email sent.",
                 "expires_in_minutes": settings.TOKEN_TTL_MINUTES},
                status=status.HTTP_201_CREATED
            )

class LoginView(APIView):
    from time import time
    throttle_scope = 'login'
    throttle_classes = [ScopedRateThrottle]
    permission_classes = [AllowAny]
    authentication_classes = []

    # @extend_schema(
    #     operation_id="auth_login",
    #     summary="User Login",
    #     description="Authenticates a user and returns an access token.",
    #     request=LoginSerializer,
    #     responses={
    #         status.HTTP_200_OK: OpenApiResponse(description="Login successful"),
    #         status.HTTP_400_BAD_REQUEST: OpenApiResponse(description="Validation error"),
    #         status.HTTP_429_TOO_MANY_REQUESTS: OpenApiResponse(
    #             response=rate_limited_schema,
    #             description="Rate limited"
    #         ),
    #     },
    #     tags=["Login"],
    # )
    @extend_schema(
        auth=[],
        operation_id="auth_login",
        tags=["Login"],
        summary="User Login",
        description="Authenticate with email & password. Returns access/refresh tokens and a minimal user profile.",
        # ---- Request schema (inline, no dedicated Serializer class) ----
        request=inline_serializer(
            name="LoginRequest",
            fields={
                "email": drf_serializers.EmailField(),
                "password": drf_serializers.CharField(write_only=True, min_length=8),
            },
        ),
        # ---- Responses with inline schemas & examples ----
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=inline_serializer(
                    name="LoginSuccess",
                    fields={
                        "access_token": drf_serializers.CharField(required = False),
                        "refresh_token": drf_serializers.CharField(required = False),
                        "user": inline_serializer(
                            name="user_details",
                            fields={
                                "uid": drf_serializers.CharField(required = False),
                                "email": drf_serializers.EmailField(required = False),
                                "is_platform_staff": drf_serializers.BooleanField(required = False),
                                "is_platform_admin": drf_serializers.BooleanField(required = False),
                            },
                            required = False
                        ),
                        "role": drf_serializers.ChoiceField(required = False, choices=["owner", "admin", "staff", "platform_admin"], help_text="User account(owner, admin, staff) , Admin account (platform_admin)"),  # e.g., "user"
                        "account": inline_serializer(
                            name="acc_details",
                            fields={
                                "id": drf_serializers.CharField(help_text="Account UUID/string ID", required = False),
                                "name": drf_serializers.CharField(required = False),
                                "status": drf_serializers.CharField(required = False),
                                # Add any other fields your login actually returns, e.g.:
                                # "status": drf_serializers.CharField(required=False),
                                # "created_at": drf_serializers.DateTimeField(required=False),
                            },
                            required = False
                        ),
                    },
                ),
                description="Login successful",
                examples=[
                    OpenApiExample(
                        name="Success",
                        summary="Successful login",
                        value={
                            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                            "user": {
                                "uid": "0c9be2a6-0d2c-4e9d-9a0b-3ee77f7e9a9b",
                                "email": "jane.doe@example.com",
                                "is_platform_staff": False,
                                "is_platform_admin": False
                            },
                            "role": "user",
                            "account": {
                                "id": "8a5a1d79-0ad6-49e7-8c1a-4b4b5a7f0f30",
                                "name": "Jane's Workspace",
                                "status": "active"
                            }
                        },
                    )
                ],
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=inline_serializer(
                    name="LoginError",
                    fields={"detail": drf_serializers.CharField(required = False)},
                ),
                description="Validation or credential error",
                examples=[
                    OpenApiExample(
                        name="InvalidCredentials",
                        summary="Wrong email/password",
                        value={"detail": "Invalid credentials"},
                    )
                ],
            ),
            status.HTTP_429_TOO_MANY_REQUESTS: OpenApiResponse(
                description="Rate limited"
            ),
        },
    )
    def post(self, request):
        s = LoginSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        return Response({
            "access_token": s.validated_data["access_token"],
            "refresh_token": s.validated_data["refresh_token"],
            "user": s.validated_data["user"],
            "role": s.validated_data["role"],
            "account": s.validated_data["account"],
        }, status=200)


class VerifyView(APIView):
    @extend_schema(
        auth=[],
        operation_id="auth_verify",
        summary="Verify email & create account",
        description="Consumes a verification token, creates User + Account, and starts a 30-day Starter trial.",
        parameters=[
            OpenApiParameter(
                name="token",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                required=True,
                description="Verification token received by email"
            )
        ],
        responses={status.HTTP_200_OK: OpenApiResponse(description="Verification succeeded")},
        tags=["Registration"],
    )
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
            # NEW: assign Starter trial (30 days)
            create_starter_trial(account)

            # mark used + delete the temp row
            tmp.is_used = True
            tmp.save(update_fields=["is_used", "updated_at"])
            tmp.delete()

        return Response(
            {"message": "Email verified. Your account has been created.", "user_id": str(user.uid), "account_id": str(account.id)},
            status=status.HTTP_200_OK
        )


class AdminVerifyView(APIView):
    @extend_schema(
        auth=[],
        operation_id="auth_verify",
        summary="Verify email & create account",
        description="Consumes a verification token, creates User + Account, and starts a 30-day Starter trial.",
        parameters=[
            OpenApiParameter(
                name="token",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                required=True,
                description="Verification token received by email"
            )
        ],
        responses={status.HTTP_200_OK: OpenApiResponse(description="Verification succeeded")},
        tags=["Registration"],
    )
    def get(self, request):
        serializer = VerifySerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]

        # Lock the temp row to avoid double consumption
        with transaction.atomic():
            try:
                tmp = TempAdmin.objects.select_for_update().get(verification_token=token, is_used=False)
            except TempAdmin.DoesNotExist:
                return Response({"detail": "Invalid or already used token."}, status=status.HTTP_400_BAD_REQUEST)

            if tmp.token_expires_at < timezone.now():
                return Response({"detail": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST)

            # Create permanent User + Account + AccountUser
            tz = country_to_tz(tmp.country)
            ## ---> If admin registration
            
            user = User.objects.create(
                first_name=tmp.first_name,
                last_name=tmp.last_name,
                email=tmp.email.lower(),
                is_platform_staff = tmp.is_platform_staff,
                is_platform_admin = tmp.is_platform_admin,
                password=tmp.password_hash,  # already hashed
                timezone=tz,
            )

            # mark used + delete the temp row
            tmp.is_used = True
            tmp.save(update_fields=["is_used", "updated_at"])
            tmp.delete()

        return Response(
            {"message": "Email verified. Your Adminaccount has been created.", "user_id": str(user.uid)},
            status=status.HTTP_200_OK
        )


class EnhancedPageNumberPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 200
    page_query_param = "page"

    def get_paginated_response(self, data):
        effective_size = self.get_page_size(self.request) or self.page.paginator.per_page
        return Response({
            "page": self.page.number,
            "page_size": int(effective_size),
            "total_pages": self.page.paginator.num_pages,
            "total_items": self.page.paginator.count,
            "next": self.get_next_link(),
            "previous": self.get_previous_link(),
            "results": data,
        }, status=status.HTTP_200_OK)


# ----------------------- Query parameters (spectacular) -----------------------
page_param = OpenApiParameter(
    name="page",
    type=OpenApiTypes.INT,
    location=OpenApiParameter.QUERY,
    description="Page number (1-based)",
    required=False,
    default=1,
)

page_size_param = OpenApiParameter(
    name="page_size",
    type=OpenApiTypes.INT,
    location=OpenApiParameter.QUERY,
    description="Items per page (max 200)",
    required=False,
    default=20,
)

search_param = OpenApiParameter(
    name="search",
    type=OpenApiTypes.STR,
    location=OpenApiParameter.QUERY,
    description="Search by name or status (icontains)",
    required=False,
)

ordering_param = OpenApiParameter(
    name="ordering",
    type=OpenApiTypes.STR,
    location=OpenApiParameter.QUERY,
    description="Order by one field: name | -name | created_at | -created_at | status | -status",
    required=False,
    default="-created_at",
)
# account_header_param = OpenApiParameter(
#     name="X-Account-ID",
#     type=OpenApiTypes.STR,
#     location=OpenApiParameter.HEADER,
#     required=False,
#     description="Active account ID (used by AccountMembershipMiddleware). "
#                 "If omitted and you have exactly one active membership, it will be auto-selected."
# )
# -----------------------------------------------------------------------------


class ListOfAccountsView(APIView):
    permission_classes = [IsAuthenticated, IsPlatformAdminOrStaff]
    @extend_schema(
        summary="List of accounts",
        description="Returns paginated accounts with search and ordering.",
        parameters=[page_param, page_size_param, search_param, ordering_param],
        responses={200: OpenApiResponse(response=PaginatedAccountResponseSerializer)},
        tags=["Customer Accounts"],
        
    )
    def get(self, request):
        # Multi-tenant safety (adjust to your auth model):
        # if getattr(request.user, "is_platform_admin", False):
        #     qs = Account.objects.all()
        # else:
        #     qs = Account.objects.filter(memberships__user=request.user).distinct()

        # # Optional search
        # search = request.query_params.get("search")
        # if search:
        #     qs = qs.filter(Q(name__icontains=search) | Q(status__icontains=search))

        qs = Account.objects.all()

        # Safe ordering whitelist
        ordering = request.query_params.get("ordering", "-created_at")
        allowed = {"name", "-name", "created_at", "-created_at", "status", "-status"}
        if ordering not in allowed:
            ordering = "-created_at"
        qs = qs.order_by(ordering)

        # Pagination
        paginator = EnhancedPageNumberPagination()
        page = paginator.paginate_queryset(qs, request, view=self)
        data = AccountListItemSerializer(page, many=True).data
        return paginator.get_paginated_response(data)

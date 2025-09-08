# accounts/serializers.py
from django.utils import timezone
from rest_framework import serializers
from .models import User, TempUser, Account, AccountUser, TempAdmin
from django.contrib.auth.hashers import make_password, check_password
from .utils import generate_access_token, generate_refresh_token
from rest_framework.exceptions import AuthenticationFailed
from django.db import transaction
from .email_sender import send_verification_email
from django.db.models import Q
from drf_spectacular.utils import extend_schema_field

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    # optional: to force a specific account when user has many
    account_id = serializers.UUIDField(required=False, allow_null=True)

    def validate(self, data):
        email = data["email"].strip().lower()
        password = data["password"]
        account_id = data.get("account_id")

        # Find active memberships for this email
        qs = AccountUser.objects.select_related("user", "account")\
                                .filter(user__email=email,
                                        is_active=True,
                                        account__status="active")

        if account_id:
            qs = qs.filter(account_id=account_id)

        memberships = list(qs)

        # If no membership, we might still allow platform staff/admin to log in
        if not memberships:
            try:
                user = User.objects.get(email=email, is_active=True)
            except User.DoesNotExist:
                raise AuthenticationFailed("Invalid credentials ss")

            if not check_password(password, user.password):
                raise AuthenticationFailed("Invalid credentials dd")

            if user.is_platform_admin or user.is_platform_staff:
                # platform-only login (no account context)
                access = generate_access_token(user)            # or generate_access_token(user, account_id=None)
                refresh = generate_refresh_token(user)
                return {
                    "access_token": access,
                    "refresh_token": refresh,
                    "user": {
                        "uid": str(user.uid),
                        "email": user.email,
                        "is_platform_staff": user.is_platform_staff,
                        "is_platform_admin": user.is_platform_admin,
                    },
                    "role": "platform_admin",
                    "account": None,
                }
            # Not platform, no memberships
            raise AuthenticationFailed("No active account membership found")

        # Choose the membership
        if account_id:
            membership = memberships[0]
        else:
            # Pick best membership by role priority, then oldest account
            role_priority = {"owner": 0, "admin": 1, "staff": 2}
            memberships.sort(key=lambda m: (role_priority.get(m.role, 99), m.account.created_at))
            membership = memberships[0]

        user = membership.user

        # Password check on the joined user
        if not check_password(password, user.password):
            raise AuthenticationFailed("Invalid credentials rr")

        # If your token functions support embedding account_id, pass it along
        acc_id = str(membership.account_id)
        try:
            access = generate_access_token(user, account_id=acc_id)    # preferred
            refresh = generate_refresh_token(user, account_id=acc_id)
        except TypeError:
            # fallback if your functions only accept (user)
            access = generate_access_token(user)
            refresh = generate_refresh_token(user)

        return {
            "access_token": access,
            "refresh_token": refresh,
            "user": {
                "uid": str(user.uid),
                "email": user.email,
                "is_platform_staff": user.is_platform_staff,
                "is_platform_admin": user.is_platform_admin,
            },
            "role": membership.role,
            "account": {
                "id": acc_id,
                "name": membership.account.name,
                "status": membership.account.status,
            },
        }

class UserRegisterSerializer(serializers.Serializer):
    # keep registration minimal
    first_name = serializers.CharField(max_length=100)
    last_name  = serializers.CharField(max_length=100)
    email      = serializers.EmailField()
    password   = serializers.CharField(min_length=8, write_only=True)

    # optional
    account_name = serializers.CharField(max_length=160, required=False, allow_blank=True)
    country      = serializers.CharField(max_length=50, required=True, allow_blank=False)

    def validate_email(self, v):
        if not v:
            raise serializers.ValidationError("Email is required.")
        v = v.lower()
        if User.objects.filter(email=v).exists():
            raise serializers.ValidationError("Email already registered.")
        # deny if an active temp exists and not yet expired
        exists_active = TempUser.objects.filter(email=v, is_used=False, token_expires_at__gt=timezone.now()).exists()
        if exists_active:
            raise serializers.ValidationError("A verification email was already sent. Please check your email inbox.")
        exists_expired = TempUser.objects.filter(email=v, is_used=False, token_expires_at__lt=timezone.now()).first()
        if exists_expired:
            # If an expired temp exists, we can reuse it
            exists_expired.delete()
        return v
    
    @transaction.atomic
    def create(self, validated_data):
        # Create TempUser only (no real User yet)
        password_hash = make_password(validated_data["password"])
        tmp = TempUser.create_temp(
            email=validated_data["email"],
            password_hash=password_hash,
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            account_name=validated_data.get("account_name", ""),
            country=validated_data.get("country") or None,
            ttl_minutes=self.context.get("ttl_minutes", 10),
        )
        send_verification_email(tmp)
        return tmp

class AdminRegisterSerializer(serializers.Serializer):
    # keep registration minimal
    first_name = serializers.CharField(max_length=100)
    last_name  = serializers.CharField(max_length=100)
    email      = serializers.EmailField()
    password   = serializers.CharField(min_length=8, write_only=True)

    # optional
    is_platform_staff = serializers.CharField(required=True, allow_null=False, help_text = '"true" or "false"')
    is_platform_admin = serializers.CharField(required=True, allow_null=False, help_text = '"true" or "false"')

    country = serializers.CharField(max_length=50, required=True, allow_blank=False)

    def validate_email(self, v):
        if not v:
            raise serializers.ValidationError("Email is required.")
        v = v.lower()
        if User.objects.filter(Q(email = v) & (Q(is_platform_staff=True) | Q(is_platform_admin=True))).exists():
            
            raise serializers.ValidationError("Email already registered for a Business Admin.")
        # deny if an active temp exists and not yet expired
        exists_active = TempAdmin.objects.filter(email=v, is_used=False, token_expires_at__gt=timezone.now()).exists()
        if exists_active:
            raise serializers.ValidationError("A verification email was already sent. Please check your email inbox.")
        exists_expired = TempAdmin.objects.filter(email=v, is_used=False, token_expires_at__lt=timezone.now()).first()
        if exists_expired:
            # If an expired temp exists, we can reuse it
            exists_expired.delete()
        return v
    
    def validate(self, attrs):
        if not attrs.get("is_platform_staff") or not attrs.get("is_platform_admin"):
            raise serializers.ValidationError("Both role flags must be provided.")
        
        staff = True if attrs.get("is_platform_staff").lower() == "true" else False
        admin = True if attrs.get("is_platform_admin").lower() == "true" else False

        if staff is None or admin is None:
            raise serializers.ValidationError("Both role flags must be provided.")

        # Enforce exactly one True
        if staff == admin:  # both True or both False
            raise serializers.ValidationError("Select exactly one role: Staff or Admin (not both).")
        
        attrs['admin'] = admin
        attrs['staff'] = staff

        return attrs

    def create(self, validated_data):
        # Create TempUser only (no real User yet)
        password_hash = make_password(validated_data["password"])
        tmp = TempAdmin.create_temp_admin(
            email=validated_data["email"],
            password_hash=password_hash,
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            is_platform_staff=validated_data.get("staff"),
            is_platform_admin=validated_data.get("admin"),
            country = validated_data["country"],
            ttl_minutes=self.context.get("ttl_minutes", 10),
        )
        return tmp


class VerifySerializer(serializers.Serializer):
    token = serializers.CharField()

class AccountListItemSerializer(serializers.Serializer):
    id = serializers.UUIDField(source="pk")
    name = serializers.CharField()
    status = serializers.CharField()
    created_at = serializers.DateTimeField()

class UserAccountMembershipSerializer(serializers.Serializer):
    id = serializers.UUIDField(source="account.id")
    name = serializers.CharField(source="account.name")
    role = serializers.CharField()          # "owner" | "admin" | "staff"
    is_active = serializers.BooleanField()  # membership status

class UserListItemSerializer(serializers.Serializer):
    id = serializers.UUIDField(source="pk")
    first_name = serializers.CharField()
    last_name  = serializers.CharField()
    email      = serializers.EmailField()

    # optional profile fields (can be completed later)
    phone      = serializers.CharField()
    street     = serializers.CharField()
    city       = serializers.CharField()
    postalCode = serializers.CharField()
    country    = serializers.CharField()
    timezone   = serializers.CharField(default="UTC")
    created_at = serializers.DateTimeField()

    # NEW: all accounts (via memberships)
    accounts   = serializers.SerializerMethodField()
    @extend_schema_field(UserAccountMembershipSerializer(many=True))

    def get_accounts(self, obj):
        # Expect related_name='memberships' on AccountUser.user
        memberships = getattr(obj, "memberships", None)
        if memberships is None:
            # Fallback if related_name wasn't set; avoid blowing up
            from .models import AccountUser
            memberships = AccountUser.objects.filter(user=obj).select_related("account")

        return UserAccountMembershipSerializer(memberships.all(), many=True).data

class PaginatedAccountResponseSerializer(serializers.Serializer):
    page = serializers.IntegerField()
    page_size = serializers.IntegerField()
    total_pages = serializers.IntegerField()
    total_items = serializers.IntegerField()
    next = serializers.CharField(allow_null=True)
    previous = serializers.CharField(allow_null=True)
    results = AccountListItemSerializer(many=True)


class PaginatedUserResponseSerializer(serializers.Serializer):
    page = serializers.IntegerField()
    page_size = serializers.IntegerField()
    total_pages = serializers.IntegerField()
    total_items = serializers.IntegerField()
    next = serializers.CharField(allow_null=True)
    previous = serializers.CharField(allow_null=True)
    results = UserListItemSerializer(many=True)




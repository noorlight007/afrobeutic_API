# accounts/models.py
import uuid
from django.db import models
from django.utils import timezone
from django.db.models import Q

class User(models.Model):
    uid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # required at registration
    first_name = models.CharField(max_length=100)
    last_name  = models.CharField(max_length=100)
    email      = models.EmailField(unique=True)
    password   = models.CharField(max_length=128)  # already hashed before save

    # optional profile fields (can be completed later)
    phone      = models.CharField(max_length=15, unique=True, null=True, blank=True)
    street     = models.CharField(max_length=250, null=True, blank=True)
    city       = models.CharField(max_length=50, null=True, blank=True)
    postalCode = models.CharField(max_length=20, null=True, blank=True)
    country    = models.CharField(max_length=50, null=True, blank=True)
    timezone   = models.CharField(max_length=50, default="UTC")

    is_active  = models.BooleanField(default=True)
    is_platform_staff = models.BooleanField(default=False)
    is_platform_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email

# ---- Account & membership (for owning salons etc.) ----
class Account(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=160)
    status = models.CharField(max_length=16, default="active")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class AccountUser(models.Model):
    ROLE_CHOICES = (("owner", "Owner"), ("admin", "Admin"), ("staff", "Staff"))
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="memberships")
    user    = models.ForeignKey(User, on_delete=models.CASCADE, related_name="memberships")
    role    = models.CharField(max_length=16, choices=ROLE_CHOICES, default="owner")
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["account", "user"], name="uniq_account_user")]


# ---- TempUser for email verification (deleted after success) ----
class TempUser(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # only the fields we need to create a real User + Account later
    email      = models.CharField(max_length=128)
    password_hash = models.CharField(max_length=128)
    first_name = models.CharField(max_length=100)
    last_name  = models.CharField(max_length=100)
    account_name = models.CharField(max_length=160, blank=True)

    # optional at register
    country    = models.CharField(max_length=50, null=True, blank=True)

    # verification
    verification_token = models.CharField(max_length=200, unique=True)
    token_expires_at   = models.DateTimeField()
    is_used            = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    @classmethod
    def create_temp(cls, *, email, password_hash, first_name, last_name, account_name="", country=None, ttl_minutes=60):
        import secrets
        token = secrets.token_urlsafe(32)
        return cls.objects.create(
            email=email.lower(),
            password_hash=password_hash,
            first_name=first_name,
            last_name=last_name,
            account_name=account_name or f"{first_name or email.split('@')[0]}'s Account",
            country=country,
            verification_token=token,
            token_expires_at=timezone.now() + timezone.timedelta(minutes=ttl_minutes),
        )


class TempAdmin(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # only the fields we need to create a real User + Account later
    email      = models.CharField(max_length=128)
    password_hash = models.CharField(max_length=128)
    first_name = models.CharField(max_length=100)
    last_name  = models.CharField(max_length=100)

    is_platform_staff = models.BooleanField()
    is_platform_admin = models.BooleanField()

    # verification
    verification_token = models.CharField(max_length=200, unique=True)
    token_expires_at   = models.DateTimeField()
    is_used            = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    @classmethod
    def create_temp_admin(cls, *, email, password_hash, first_name, last_name, is_platform_staff, is_platform_admin, ttl_minutes=60):
        import secrets
        token = secrets.token_urlsafe(32)
        return cls.objects.create(
            email=email.lower(),
            password_hash=password_hash,
            first_name=first_name,
            last_name=last_name,
            is_platform_staff=is_platform_staff,
            is_platform_admin=is_platform_admin,
            verification_token=token,
            token_expires_at=timezone.now() + timezone.timedelta(minutes=ttl_minutes),
        )
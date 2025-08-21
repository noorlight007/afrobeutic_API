# accounts/serializers.py
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from rest_framework import serializers
from .models import User, TempUser, Account, AccountUser

COUNTRY_TZ_MAP = {
    'united states': 'America/New_York',
    'bangladesh': 'Asia/Dhaka',
    'india': 'Asia/Kolkata',
    'france': 'Europe/Paris',
    'germany': 'Europe/Berlin',
}

class UserRegisterSerializer(serializers.Serializer):
    # keep registration minimal
    first_name = serializers.CharField(max_length=100)
    last_name  = serializers.CharField(max_length=100)
    email      = serializers.EmailField()
    password   = serializers.CharField(min_length=8, write_only=True)

    # optional
    account_name = serializers.CharField(max_length=160, required=False, allow_blank=True)
    country      = serializers.CharField(max_length=50, required=False, allow_blank=True)

    def validate_email(self, v):
        v = v.lower()
        if User.objects.filter(email=v).exists():
            raise serializers.ValidationError("Email already registered.")
        # deny if an active temp exists and not yet expired
        exists_active = TempUser.objects.filter(email=v, is_used=False, token_expires_at__gt=timezone.now()).exists()
        if exists_active:
            raise serializers.ValidationError("A verification email was already sent. Please check your email inbox.")
        return v

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
            ttl_minutes=self.context.get("ttl_minutes", 60),
        )
        return tmp


class VerifySerializer(serializers.Serializer):
    token = serializers.CharField()

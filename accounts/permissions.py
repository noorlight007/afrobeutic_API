from rest_framework.permissions import BasePermission
from .models import Account, AccountUser

def _real_user(request_user):
    """Unwrap _AuthUserAdapter -> real Django user instance."""
    return getattr(request_user, "_u", request_user)

class AttachAccountContext(BasePermission):
    header_key = "HTTP_X_ACCOUNT_ID"
    query_key = "account_id"

    def has_permission(self, request, view):
        # always initialize
        request.account = None
        request.account_membership = None

        u = getattr(request, "user", None)
        if not u or not getattr(u, "is_authenticated", False):
            return False  # let IsAuthenticated handle

        real_user = _real_user(u)
        # use primary key for FK lookups (safer than passing the adapter)
        user_pk = getattr(real_user, "pk", None)
        if not user_pk:
            return False

        account_id = request.META.get(self.header_key) or request.GET.get(self.query_key)

        # ✅ use user_id, not user=...
        memberships = AccountUser.objects.filter(user_id=user_pk, is_active=True)

        account = None
        if account_id:
            try:
                account = Account.objects.get(pk=account_id)
            except Account.DoesNotExist:
                return False
        else:
            ids = list(memberships.values_list("account_id", flat=True).distinct())
            if len(ids) == 1:
                account = Account.objects.filter(pk=ids[0]).first()

        request.account = account
        if account:
            request.account_membership = memberships.filter(account=account).first()

        return True


class IsPlatformAdminOrStaff(BasePermission):
    """1) is_platform_admin OR is_platform_staff"""
    def has_permission(self, request, view):
        u = getattr(request, "user", None)
        return bool(
            u and getattr(u, "is_authenticated", False) and
            (getattr(u, "is_platform_admin", False) or getattr(u, "is_platform_staff", False))
        )


class IsPlatformAdminOnly(BasePermission):
    """2) is_platform_admin"""
    def has_permission(self, request, view):
        u = getattr(request, "user", None)
        return bool(u and getattr(u, "is_authenticated", False) and getattr(u, "is_platform_admin", False))


def _has_role(request, allowed: set[str]) -> bool:
    m = getattr(request, "account_membership", None)
    if not (getattr(request, "user", None) and getattr(request.user, "is_authenticated", False) and m and m.is_active):
        return False
    role = (getattr(m, "role", "") or "").strip().lower()
    return role in allowed


class IsAccountOwner(BasePermission):
    """3) role == owner"""
    def has_permission(self, request, view):
        return _has_role(request, {"owner"})


class IsAccountOwnerOrAdmin(BasePermission):
    """4) role in {owner, admin}"""
    def has_permission(self, request, view):
        return _has_role(request, {"owner", "admin"})


class IsAccountOwnerAdminOrStaff(BasePermission):
    """5) role in {owner, admin, staff}"""
    def has_permission(self, request, view):
        return _has_role(request, {"owner", "admin", "staff"})

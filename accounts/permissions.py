# accounts/permissions.py
from rest_framework.permissions import BasePermission

class IsPlatformAdminOrStaff(BasePermission):
    """1) is_platform_admin OR is_platform_staff"""
    def has_permission(self, request, view):
        u = getattr(request, "user", None)
        return bool(u and u.is_authenticated and (getattr(u, "is_platform_admin", False) or getattr(u, "is_platform_staff", False)))

class IsPlatformAdminOnly(BasePermission):
    """2) is_platform_admin"""
    def has_permission(self, request, view):
        u = getattr(request, "user", None)
        print(u)
        return bool(u and u.is_authenticated and getattr(u, "is_platform_admin", False))

def _has_role(request, allowed: set[str]) -> bool:
    m = getattr(request, "account_membership", None)
    if not (getattr(request, "user", None) and request.user.is_authenticated and m and m.is_active):
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

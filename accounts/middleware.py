# accounts/middleware.py
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from .models import Account, AccountUser

class AccountMembershipMiddleware(MiddlewareMixin):
    """
    Resolve the active account & membership so we can read the role.
    Priority:
      1) Header: X-Account-ID
      2) Query:  ?account_id=...
      3) If user has exactly one active membership, pick that
    Attaches:
      request.account (Account or None)
      request.account_membership (AccountUser or None)
    """
    header_key = "HTTP_X_ACCOUNT_ID"
    query_key = "account_id"

    def process_request(self, request):
        request.account = None
        request.account_membership = None

        u = getattr(request, "user", None)
        print(u)
        if not u or not u.is_authenticated:
            print("damn.")
            return

        account_id = request.META.get(self.header_key) or request.GET.get(self.query_key)
        memberships = AccountUser.objects.filter(user=u, is_active=True)

        account = None
        if account_id:
            try:
                account = Account.objects.get(pk=account_id)
            except Account.DoesNotExist:
                return JsonResponse({"detail": "Invalid X-Account-ID / account_id."}, status=400)
        else:
            ids = list(memberships.values_list("account_id", flat=True).distinct())
            if len(ids) == 1:
                account = Account.objects.filter(pk=ids[0]).first()

        request.account = account
        if account:
            request.account_membership = memberships.filter(account=account).first()

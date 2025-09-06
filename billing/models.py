import uuid
from django.db import models
from django.utils import timezone

# ---- Plans -------------------------------------------------------
class Plan(models.Model):

    CODE_CHOICES = [
        ("starter", "Starter"),
        ("growth", "Growth"),
        ("enterprise", "Enterprise"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=40, choices=CODE_CHOICES, unique=True)
    name = models.CharField(max_length=80)

    # price per month (in cents, integer to avoid float issues)
    price_cents = models.PositiveIntegerField(default=0)

    # JSON features: { "max_salons": 1, "max_employees": 30, ... }
    features = models.JSONField(default=dict, blank=True)

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name}"


# ---- Subscriptions -----------------------------------------------
class Subscription(models.Model):
    """A subscription instance. Core plan = 1 per account."""
    STATUS = [
        ("trialing", "Trialing"),
        ("active", "Active"),
        ("past_due", "Past Due"),
        ("canceled", "Canceled"),
        ("paused", "Paused"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    account = models.ForeignKey("accounts.Account", on_delete=models.CASCADE, related_name="subscriptions")
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT, related_name="subscriptions")
    status = models.CharField(max_length=16, choices=STATUS, default="active")

    # Billing periods (UTC)
    current_period_start = models.DateTimeField(default=timezone.now)
    current_period_end = models.DateTimeField()
    cancel_at_period_end = models.BooleanField(default=False)

    trial_ends_at = models.DateTimeField(null=True, blank=True)
    

    # Optional links to external provider (Stripe, etc.)
    provider = models.CharField(max_length=20, blank=True, default="")
    provider_customer_id = models.CharField(max_length=80, blank=True, default="")
    provider_subscription_id = models.CharField(max_length=80, blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["account", "status"]),
        ]

    def __str__(self):
        return f"{self.account_id} -> {self.plan.code} [{self.status}]"
    
    @property
    def in_trial(self) -> bool:
        return self.status == "trialing" and (self.trial_ends_at and self.trial_ends_at > timezone.now())

# class MessageMonthlyUsage(models.Model):
#     """
#     Tracks included messages used for (account, salon, month).
#     Resets by month. Overage beyond included is charged to wallet.
#     """
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     account = models.ForeignKey("accounts.Account", on_delete=models.CASCADE)
#     salon = models.ForeignKey("salons.Salon", on_delete=models.CASCADE)
#     year = models.PositiveSmallIntegerField()
#     month = models.PositiveSmallIntegerField()  # 1..12
#     used = models.PositiveIntegerField(default=0)

#     class Meta:
#         unique_together = [("account", "salon", "year", "month")]


# class TemplateMessageMonthlyUsage(models.Model):
#     """
#     Tracks included template messages used for (account, salon, month).
#     Resets by month. Overage beyond included is charged to wallet.
#     """
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     account = models.ForeignKey("accounts.Account", on_delete=models.CASCADE)
#     salon = models.ForeignKey("salons.Salon", on_delete=models.CASCADE)
#     year = models.PositiveSmallIntegerField()
#     month = models.PositiveSmallIntegerField()  # 1..12
#     used = models.PositiveIntegerField(default=0)

#     class Meta:
#         unique_together = [("account", "salon", "year", "month")]
    

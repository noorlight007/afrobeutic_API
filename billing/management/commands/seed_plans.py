# billing/management/commands/seed_plans.py
from django.core.management.base import BaseCommand
from billing.models import Plan

STARTER_FEATURES = {
    "max_salons": 1,
    "per_salon": {
        "max_employees": 15,
        "max_products": 30,
        "max_styles": 30,
        "included_chatbot": True,
        "included_messages": 800,
        "included_template_messages": 50,   # <= your request
    },
    "overage": {
        "whatsapp_message_cents": 1,
        "whatsapp_template_messages_cents": 80,
    }
}

GROWTH_FEATURES = {
    "max_salons": 2,
    "per_salon": {
        "max_employees": 15,         # same “starter item” per salon
        "max_products": 30,
        "max_styles": 30,
        "included_chatbot": True,
        "included_messages": 800,
        "included_template_messages": 50,
    },
    "overage": {
        "whatsapp_message_cents": 30,
        "whatsapp_template_messages_cents": 80,
    }
}

ENTERPRISE_FEATURES = {
    "max_salons": None,              # unlimited / custom
    "per_salon": {
        "max_employees": None,
        "max_products": None,
        "max_styles": None,
        "included_chatbot": True,
        "included_messages": None,    # set None if you want fully custom
        "included_template_messages": None,
    },
    "overage": {
        "whatsapp_message_cents": None,
        "whatsapp_template_messages_cents": None,
    }
}

class Command(BaseCommand):
    help = "Seed core plans (Starter, Growth, Enterprise) with features"

    def handle(self, *args, **kwargs):
        plans = [
            dict(code="starter",    name="Starter",    price_cents=2500, features=STARTER_FEATURES),
            dict(code="growth",     name="Growth",     price_cents=5000, features=GROWTH_FEATURES),
            dict(code="enterprise", name="Enterprise", price_cents=0,    features=ENTERPRISE_FEATURES),
        ]
        for p in plans:
            obj, created = Plan.objects.update_or_create(code=p["code"], defaults=p)
            self.stdout.write(self.style.SUCCESS(f"{'Created' if created else 'Updated'} plan: {obj.code}"))

from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        # make sure the extension class is imported so drf-spectacular can register it
        from . import openapi  # noqa: F401

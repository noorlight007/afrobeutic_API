# accounts/urls.py
from django.urls import path
from .views import ListOfAccountsView, RegisterView, VerifyView, LoginView
from .views_token import RefreshTokenView, TokenVerifyView

app_name = "accounts"

urlpatterns = [
    path("auth/register", RegisterView.as_view(), name="register"),
    path("auth/login", LoginView.as_view(), name="login"),
    path("auth/verify",   VerifyView.as_view(),   name="verify"),
    path("list/accounts",   ListOfAccountsView.as_view(),   name="list_accounts"),

    path("auth/token/refresh", RefreshTokenView.as_view(), name="auth_token_refresh"),
    path("auth/token/verify", TokenVerifyView.as_view(), name="auth_token_verify"),
]

# accounts/urls.py
from django.urls import path
from .views import ListOfAccountsView, RegisterView, VerifyView, LoginView

app_name = "accounts"

urlpatterns = [
    path("auth/register", RegisterView.as_view(), name="register"),
    path("auth/login", LoginView.as_view(), name="login"),
    path("auth/verify",   VerifyView.as_view(),   name="verify"),
    path("list/accounts",   ListOfAccountsView.as_view(),   name="list_accounts"),
]

# accounts/urls.py
from django.urls import path
from .views import RegisterView, VerifyView

app_name = "accounts"

urlpatterns = [
    path("auth/register", RegisterView.as_view(), name="register"),
    path("auth/verify",   VerifyView.as_view(),   name="verify"),
]

# main_app/urls.py

from django.urls import path, include
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)

urlpatterns = [
    # your APIs
    path("api/v1/accounts/", include("accounts.urls", namespace="accounts")),

    # raw OpenAPI schema (JSON by default; add ?format=yaml for YAML)
    # Raw OpenAPI schema (json/yaml)
   path("api/v1/schema/", SpectacularAPIView.as_view(api_version="v1"), name="schema"),


    # Swagger UI
    path("api/v1/swagger/", SpectacularSwaggerView.as_view(url_name="schema"), name="schema-swagger-ui"),

    # ReDoc
    path("api/v1/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="schema-redoc"),
]

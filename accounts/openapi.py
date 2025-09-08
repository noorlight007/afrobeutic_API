# accounts/openapi.py
from drf_spectacular.extensions import OpenApiAuthenticationExtension

class SimpleBearerAccessTokenAuthenticationScheme(OpenApiAuthenticationExtension):
    """
    Tell drf-spectacular how to represent our custom Bearer auth in OpenAPI.
    """
    target_class = 'accounts.authentication.SimpleBearerAccessTokenAuthentication'
    name = 'SimpleBearerAccessTokenAuthentication'

    def get_security_definition(self, auto_schema):
        return {
            'type': 'http',
            'scheme': 'bearer',
            'bearerFormat': 'JWT',
        }

# afrobeutic_apis/openapi_hooks.py

def add_tag_groups(result, generator, request, public):
    """
    Inject ReDoc/Swagger UI tag groups (x-tagGroups) at the root of the schema.
    This produces bold section headers in ReDoc like:
      Opportunity API
        - Opportunities
        - Lists
    """
    # Ensure the key exists at the root
    result["x-tagGroups"] = [
        {"name": "Users - Accounts", "tags": ["Accounts", "Registration"]},
        {"name": "Users - Authentication", "tags": ["Login", "Auth"]},
        {"name": "Users - Profile", "tags": ["Profile"]},
        {"name": "Afrobeutic Business Admin", "tags": ["Admins - Registration", "Admins - Login", "Admins - Auth", "Customer Accounts", "Customer Users"]},
    ]
    return result

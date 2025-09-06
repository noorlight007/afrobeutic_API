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
        {"name": "Users", "tags": ["Accounts", "Registration", "Login"]},
        {"name": "Afrobeutic Business Admin", "tags": ["Customer Accounts"]},
    ]
    return result

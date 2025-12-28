from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
   # default_auto_field = "django.db.models.BigAutoField"
    default_auto_field = "django_mongodb_backend.fields.ObjectIdAutoField"
    name = "authentication"

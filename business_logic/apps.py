from django.apps import AppConfig


class BusinessLogicConfig(AppConfig):
   # default_auto_field = 'django.db.models.BigAutoField'
    default_auto_field = "django_mongodb_backend.fields.ObjectIdAutoField"
    name = 'business_logic'

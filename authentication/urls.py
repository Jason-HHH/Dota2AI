from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import SignupView, get_csrf_token, LogoutView 

urlpatterns = [
    path("signup/", SignupView.as_view(), name="signup"),
    path("csrf-token/", get_csrf_token, name="csrf-token"),
    path("login/", TokenObtainPairView.as_view(), name="login"),
    path("token-refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
]
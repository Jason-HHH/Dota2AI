from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from .serializers import SignupSerializer

from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.decorators import api_view

from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from rest_framework.permissions import IsAuthenticated

from .serializers import SignupSerializer
# Create your views here.

class SignupView(APIView):
    # 注册接口任何人都可以访问，不需要登录
    permission_classes = [AllowAny]

    def post(self, request):
        """
        处理 POST /signup 请求：
        1. 用 SignupSerializer 校验数据
        2. 校验成功 -> 创建用户 -> 返回 200 + message
        3. 校验失败 -> 返回 400 + 错误信息
        """
        serializer = SignupSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()  # 会调用 serializer.create()
            return Response(
                {"message": "Signed up successfully"},
                status=status.HTTP_201_CREATED,
            )

        # 把错误信息返回给前端（比如用户名已被占用）
        return Response(
            {"message": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


@ensure_csrf_cookie
@api_view(["GET"])
def get_csrf_token(request):
    """
    GET /csrf-token/
    返回一个 CSRF token，并在 Cookie 里种下 csrftoken。
    前端之后把这个 token 放到 X-CSRFToken 头里即可。
    """
    token = get_token(request)
    return JsonResponse({"token": token})
    
class LogoutView(APIView):
    """
    接收 refresh token，把它加入黑名单。
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response(
                {"message": "Missing refresh token"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return Response(
                {"message": "Token is invalid or expired"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        return Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)
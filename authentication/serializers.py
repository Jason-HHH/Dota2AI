# authentication/serializers.py
from django.contrib.auth.models import User
from rest_framework import serializers


class SignupSerializer(serializers.ModelSerializer):
    # 只写入，不在返回数据里显示
    password = serializers.CharField(write_only=True, min_length=8)
    password2 = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        # 这三个字段会从请求体中读取
        fields = ["username", "email", "password", "password2"]
        extra_kwargs = {
            "email": {"required": False},
        }

    def validate_username(self, value):
        """
        验证用户名是否已存在。
        """
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("用户名已存在。")
        return value
    
    def validate_email(self, value):
        """
        验证邮箱是否已存在。
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("邮箱已存在。")
        return value
    
    def validate(self, attrs):
        if attrs['password'].lower() == attrs['username'].lower():
            raise serializers.ValidationError("密码不能与用户名相同。")
        if 'email' in attrs and attrs['password'].lower() in attrs['email'].lower():
            raise serializers.ValidationError("密码不能包含邮箱内容。")
        if attrs['password'].isdigit():
            raise serializers.ValidationError("密码不能全为数字。")
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError("两次输入的密码不一致")
        return attrs

    def create(self, validated_data):
        """
        当 serializer.save() 被调用时，会走到这里。
        使用 create_user 自动做密码哈希加密。
        """
        password = validated_data.pop("password")
        validated_data.pop("password2")
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data.get("email", ""),
            password=password,
        )
        return user

from django.contrib.auth.models import User
from rest_framework import serializers


class MatchEventsSerializer(serializers.Serializer):
    match_id = serializers.CharField(max_length=100)

    def validate_match_id(self, value):
        if not value.isalnum():
            raise serializers.ValidationError("Match ID must be alphanumeric.")
        return value
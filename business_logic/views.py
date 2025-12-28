import traceback
from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .services.match_events_service import get_match_events
from .services.vision_graph_service import get_or_create_vision_graph_url


class MatchEventsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        match_id = request.query_params.get("match_id")
        if not match_id:
            return Response(
                {"message": "match_id parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            events = get_match_events(match_id)
            return Response({"events": events}, status=status.HTTP_200_OK)
        except Exception as e:
            print("=== MatchEvents ERROR ===")
            print(e)
            print(traceback.format_exc())
            raise

class MatchVisionGraphView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        match_id = request.query_params.get("match_id")
        enemy_side = request.query_params.get("enemy_side")
        if not match_id or not enemy_side:
            return Response({"message": "match_id/enemy_side parameter is required"},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            url = get_or_create_vision_graph_url(match_id, enemy_side)

            return Response({"url": url}, status=status.HTTP_200_OK)
        except Exception as e:
            print("=== MatchEvents ERROR ===")
            print(e)
            print(traceback.format_exc())
            raise
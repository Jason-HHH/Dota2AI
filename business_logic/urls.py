from django.http import HttpResponse
from django.urls import path
from .views import MatchEventsView, MatchVisionGraphView

def ping(request):
    return HttpResponse("pong")

urlpatterns = [    
    path("ping/", ping),
    path("match_events/", MatchEventsView.as_view(), name="match_events"),
    path("match_vision_graph/", MatchVisionGraphView.as_view(), name="match_vision_graph"),
]
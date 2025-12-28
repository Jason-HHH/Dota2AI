
# Create your models here.
from django.db import models



class VisionGraph(models.Model):
    vision_graph_id = models.CharField(max_length=255, unique=True)
    url = models.CharField(max_length=512)
    date_created = models.DateTimeField("date created")
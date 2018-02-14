from django.db import models
from django.contrib.auth.models import User
from tonerecorder.models import RecordedSyllable

# Create your models here.
class RecordingGrade(models.Model):
    grader = models.ForeignKey(User)
    recording = models.ForeignKey(RecordedSyllable)
    grade = models.IntegerField()
    discard = models.BooleanField()
    button_sounds = models.BooleanField()
    background_hum = models.BooleanField()
    background_noise = models.BooleanField()
    other = models.CharField(max_length=80, null=True)

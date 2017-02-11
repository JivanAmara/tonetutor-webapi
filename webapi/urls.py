'''
Created on Sep 28, 2016

@author: jivan
'''
from django.conf.urls import url, include
from rest_framework import routers
from rest_framework.authtoken import views

from webapi import views as webapi_views
from webapi.views import AuthenticateUser, RandomSyllable, ToneCheck, GradeRecording, GetRecordingToGrade


router = routers.DefaultRouter()

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^tokenauth/?', AuthenticateUser.as_view()),
    url(r'^randomsyllable/?', RandomSyllable.as_view()),
    url(r'^tonecheck/?', ToneCheck.as_view()),
    url(r'^get_recording_to_grade/?', GetRecordingToGrade.as_view(), name='ttapi_get_recording_to_grade'),
    url(r'^grade_recording/(?P<recording_id>[\d]+)/?', GradeRecording.as_view(), name='ttapi_grade_recording'),
    url(r'^auth/', include('rest_framework.urls', namespace='rest_framework'))
]

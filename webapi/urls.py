'''
Created on Sep 28, 2016

@author: jivan
'''
from django.conf.urls import url, include
from rest_framework import routers
from rest_framework.authtoken import views

from webapi import views as webapi_views
from webapi.views import AuthenticateUser, RandomSyllable, ToneCheck


router = routers.DefaultRouter()

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^tokenauth/?', AuthenticateUser.as_view()),
    url(r'^randomsyllable/?', RandomSyllable.as_view()),
    url(r'^tonecheck/?', ToneCheck.as_view()),
    url(r'^auth/', include('rest_framework.urls', namespace='rest_framework'))
]

'''
Created on Sep 28, 2016

@author: jivan
'''
from django.conf.urls import url, include
from rest_framework import routers

from webapi.views import AuthenticateUser, RandomSyllable, ToneCheck, GradeRecording, GetRecordingToGrade, \
    AddMonthSubscription, ValidateITunesReceipt


router = routers.DefaultRouter()

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    url(r'^tokenauth/?', AuthenticateUser.as_view(), name='AuthenticateUser'),
    url(r'^randomsyllable/?', RandomSyllable.as_view()),
    url(r'^tonecheck/?', ToneCheck.as_view()),
    url(r'^pay_subscription/?$', AddMonthSubscription.as_view()),
    url(r'^pay_subscription_applepay/?$', ValidateITunesReceipt.as_view(), name='ValidateITunesReceipt'),
    url(r'^pay_subscription_applepay_test/?$', ValidateITunesReceipt.as_view(), {'use_testing_endpoint': True}, name='ValidateITunesReceiptTest'),
#     url(r'^stripe_test/?', StripeTest.as_view()),
    url(r'^get_recording_to_grade/?', GetRecordingToGrade.as_view(), name='ttapi_get_recording_to_grade'),
    url(r'^grade_recording/(?P<recording_id>[\d]+)/?', GradeRecording.as_view(), name='ttapi_grade_recording'),
    url(r'^auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^', include(router.urls)),
]

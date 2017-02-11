'''
Created on Sep 14, 2016

@author: jivan
'''
import json
from pprint import pprint
from unittest import mock

from django.contrib.auth.models import User
from django.urls import reverse, resolve
import pytest
from rest_framework.test import APIRequestFactory, force_authenticate
from tonerecorder.models import RecordedSyllable

from rest_framework.authtoken.models import Token
from webapi.models import RecordingGrade
from webapi.views import GradeRecording



def rs_get(id=None):
    # Simulates getting a model instance via id.
    # 1 returns a valid instance
    # 2 raises a DoesNotExist error
    assert id != None
    assert int(id) in [1, 2]
    if id == 1:
        i = RecordedSyllable.objects.create()
    elif id == 2:
        raise RecordedSyllable.DoesNotExist
    else:
        raise Exception('Unexpected id: {}'.format(id))

    return i

def do_nothing_save(*args, **kwargs):
    pass

@pytest.mark.django_db
class TestGradeSyllable:

    @mock.patch('webapi.views.RecordedSyllable.save', do_nothing_save)
    @mock.patch('webapi.views.RecordingGrade.save', do_nothing_save)
    @mock.patch('webapi.views.RecordedSyllable.objects.get', rs_get)
    def test_grade_existing_syllable(self, client,):
        recording_id = 1
        user = User.objects.create_user(username='joe', password='joe')
        print('User id: {}'.format(user.id))
        print('recording_id: {}'.format(recording_id))
        url = reverse('ttapi_grade_recording', kwargs={'recording_id': recording_id})
        print('Using url: {}'.format(url))
        token, _ = Token.objects.get_or_create(user=user)

        json_data = json.dumps({
            'authToken': token.key,
            'listenerId': user.id,
            'recordingId': recording_id,
            'grade': 3,
            'discard': False,
            'button_sounds': False,
            'background_hum': False,
            'background_noise': False,
            'other': 'Nothing else',
        })
        rf = APIRequestFactory()
        req = rf.post(url, json_data, content_type='application/json')
        force_authenticate(req, user=user)
        resp = client.post(url, json_data, content_type='application/json')

        assert resp.status_code == 201
        print(resp.content)
        resp_data = json.loads(resp.content.decode('utf8'))
        assert resp_data['status'] == 'ok'

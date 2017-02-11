from collections import OrderedDict
from datetime import datetime
from hashlib import md5
import json
from logging import getLogger
import os

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.staticfiles.templatetags.staticfiles import static
from django.http.response import HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
import pytz
import requests
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from syllable_samples.interface import get_random_sample
from tonerecorder.models import RecordedSyllable

from webapi.models import RecordingGrade


logger = getLogger(__name__)

class RandomSyllable(APIView):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return APIView.dispatch(self, request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        sound, tone, display, path, hanzi = get_random_sample()

        # 'css/style.css' file should exist in static path. otherwise, error will occur
        url = static(path)
        data = {
            'sound': sound,
            'tone': tone,
            'display': display,
            'hanzi': hanzi,
            'url': url
        }

        resp = HttpResponse(json.dumps(data))
        return resp

class AuthenticateUser(APIView):
    permission_classes = (AllowAny,)

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return View.dispatch(self, request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')
        if {'null', 'undefined'} & {username}:
            username = None
        if {'null', 'undefined'} & {password}:
            password = None

        if username is None or password is None:
            status_code = 401
            msgs = []
            if username is None:
                msgs.append('username is required')
            if password is None:
                msgs.append('password is required')

            resp = {
                'detail': ', '.join(msgs)
            }
        else:
            if not User.objects.filter(username=username).exists():
                User.objects.create_user(username=username, password=password)

            user = authenticate(username=username, password=password)
            if user is None:
                status_code = 401
                resp = {
                    'detail': 'Invalid password for {}.'.format(username),
                }
            else:
                token, created = Token.objects.get_or_create(user=user)
                if not created:
                    token.delete()
                    token = Token(user=user)
                    token.save()

                status_code = 200
                resp = OrderedDict([
                    ('username', user.username),
                    ('user_id', user.id),
                    ('auth_token', token.key),
                ])

        json_resp = json.dumps(resp)
        http_resp = HttpResponse(json_resp, status=status_code)
        return http_resp

class ToneCheck(APIView):
    """ Checks the value of an audio recording against the machine learning model via
        the api at settings.UPSTREAM_HOST.
        See: tonetutor.webui.views.ToneCheck for input/output details.
        Note: This view adds a field 'attempt_url' containing a url corresponding to the result's
            'attempt_path'.
    """
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return APIView.dispatch(self, request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        try:
            t = Token.objects.get(user=request.user)
            auth_token = t.key
        except Token.DoesNotExist:
            auth_token = ''

        try:
            extension = request.POST['extension']
            expected_sound = request.POST['expected_sound']
            expected_tone = request.POST['expected_tone']
            is_native = request.POST.get('is_native', False)
            attempt_claimed_md5 = request.POST.get('attempt_md5', '')
            attempt = request.FILES['attempt']

            attempt_data = attempt.read()
            m = md5()
            m.update(attempt_data)
            attempt_md5 = m.hexdigest()

            print('MD5 Claimed: {}, Actual: {}'.format(attempt_claimed_md5, attempt_md5))

            url = ''.join([
                settings.UPSTREAM_PROTOCOL, settings.UPSTREAM_HOST, settings.UPSTREAM_PATH
            ])
            try:
                r = requests.post(
                    url,
                    timeout=5,
                    headers={
                        'user_agent': 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6',
                        'authorization': 'Token ' + auth_token,
                    },
                    data={
                        'attempt': attempt_data,
                        'attempt_md5': attempt_claimed_md5,
                        'extension': extension,
                        'auth_token': auth_token,
                        'expected_sound': expected_sound,
                        'expected_tone': expected_tone, 'is_native': is_native,
                    },
                    files={'attempt': attempt_data}
                )
                try:
                    json_result = r.json()
                    # The attempt file is hosted on the upstream server
                    # Make a full url from the path returned.
                    attempt_path = json_result['attempt_path']
                    attempt_url = ''.join([
                        settings.UPSTREAM_PROTOCOL, settings.UPSTREAM_HOST, attempt_path
                    ])
                    json_result['attempt_url'] = attempt_url
                    content = json.dumps(json_result)
                except:
                    content = r.content
                status = r.status_code
            except requests.exceptions.Timeout:
                logger.error('Timeout trying to access: {}'.format(url))
                content = json.dumps({
                    'status': False,
                    'detail': 'Timeout accessing upstream server: {}'.format(settings.UPSTREAM_HOST)
                })
                status = 504  # 504: Gateway Timeout
            resp = HttpResponse(content, status=status)
            logger.info('Status {} from api call to {}'.format(r.status_code, url))
            logger.debug('Result content: {}'.format(r.content))
            hop_by_hop = ['connection', 'keep-alive', 'public', 'proxy-authenticate',
                'transfer-encoding', 'upgrade'
            ]

            for hname, hvalue in r.headers.items():
                hname = hname.lower()
                if hname == 'content-encoding' or hname in hop_by_hop:
                    # I've seen content-encoding change as the request passes through requests.
                    # Keeping it set to 'gzip' from the upstream call results in an error on
                    #    the client.
                    # hop-by-hop headers cause problems passed along from here.
                    continue
                resp[hname] = hvalue
        except KeyError:
            msg = 'Each of the following fields is required: '\
                  'attempt, extension, expected_sound, expected_tone, is_native'
            resp = HttpResponse(json.dumps({'detail': msg}), status=400)

        return resp

class GradeRecording(APIView):

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return View.dispatch(self, request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        grading_data = json.loads(request.body.decode('utf-8'))
        listener_id = grading_data['listenerId']
        grader = User.objects.get(id=listener_id)
        expected_token = Token.objects.get(user=grader)
        token = grading_data['authToken']
        # Compare utc datetime instances as naive (timezone-unaware) datetimes
        now = datetime.now(tz=pytz.utc)
        token_age_in_hours = (now - expected_token.created).total_seconds() // 3600
        if token_age_in_hours >= 24:
            json_resp = json.dumps({'status': 'fail', 'msg': 'authentication expired'})
            status_code = 403
        elif token != expected_token.key:
            json_resp = json.dumps({'status': 'fail', 'msg': 'bad auth token'})
            status_code = 403
        elif token == expected_token.key:
            print([ a for a in dir(request) if a[0] != '_'])
            recording_id = int(kwargs['recording_id'])
            recording = RecordedSyllable.objects.get(id=recording_id)

            grading = RecordingGrade(
                grader=grader,
                recording=recording,
                grade=grading_data['grade'],
                discard=grading_data.get('discard', False),
                button_sounds=grading_data.get('buttonSounds', False),
                background_hum=grading_data.get('backgroundHum', False),
                background_noise=grading_data.get('backgroundNoise', False),
                other=grading_data.get('other', None),
            )

            try:
                grading.save()
                json_resp = json.dumps({'status': 'ok'})
                status_code = 201  # Created
            except Exception as ex:
                json_resp = json.dumps({'status': 'fail', 'detail': ex})
                status_code = 500  # Internal Server Error

        resp = HttpResponse(content=json_resp, status=status_code)
        resp['Content-Type'] = 'application/json'
        return resp


def authorized(to_wrap):
    # Wraps a view function, ensuring that the user is authenticated before executing the view.
    # If the user isn't authenticated, returns a json string indicating that.
    def wrapped(request, *args, **kwargs):
        try:
            grading_data = json.loads(request.body.decode('utf-8'))
            listener_id = grading_data['listenerId']
            grader = User.objects.get(id=listener_id)
            expected_token = Token.objects.get(user=grader)
            token = grading_data['authToken']
            # Compare utc datetime instances as naive (timezone-unaware) datetimes
            now = datetime.now(tz=pytz.utc)
            token_age_in_hours = (now - expected_token.created).total_seconds() // 3600
            if token_age_in_hours >= 24:
                json_resp = json.dumps({'status': 'fail', 'msg': 'authentication expired'})
                status = 403
                resp = HttpResponse(json_resp, status_code=status)
            elif token != expected_token.key:
                json_resp = json.dumps({'status': 'fail', 'msg': 'bad auth token'})
                status = 403
                resp = HttpResponse(json_resp, status=status)
            elif token == expected_token.key:
                # Everything's good, pass through to the wrapped function
                resp = to_wrap(request, *args, **kwargs)
        except Exception as e:
            status = 500
            msg = e.message if hasattr(e, 'message') else str(e)
            json_resp = json.dumps({'status': 'fail', 'detail': 'Authorization Exception:\n{}'.format(msg)})
            resp = HttpResponse(json_resp, status=status)

        return resp

    return wrapped


class GetRecordingToGrade(APIView):

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return View.dispatch(self, request, *args, **kwargs)

    @method_decorator(authorized)
    def post(self, request, *args, **kwargs):
        grading_data = json.loads(request.body.decode('utf-8'))
        listener_id = grading_data['listenerId']
        next_recording = RecordedSyllable.objects.exclude(recordinggrade__grader__id=listener_id).order_by('id').first()

        if next_recording is None:
            json_resp = json.dumps({
                'status': 'complete', 'detail': 'No further recordings to grade now.',
            })
            status_code = 200
        else:
            audio_file_basename = os.path.basename(next_recording.audio_original)
            audio_url = os.path.join(settings.MEDIA_URL, settings.SYLLABLE_AUDIO_DIR, audio_file_basename)
            json_resp = json.dumps({
                'status': 'ok', 'recordingId': next_recording.id,
                'audioUrl': audio_url
            })
            status_code = 200

        resp = HttpResponse(json_resp, status=status_code)
        return resp

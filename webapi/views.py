from collections import OrderedDict
from hashlib import md5
import json
import os

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.staticfiles.templatetags.staticfiles import static
from django.http.response import HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
import requests
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from syllable_samples.interface import get_random_sample
from logging import getLogger

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
                token, created_ignored = Token.objects.get_or_create(user=user)
                status_code = 200
                resp = OrderedDict([
                    ('username', user.username),
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
            except requests.exceptions.Timeout:
                logger.error('Timeout trying to access: {}'.format(url))
                content = json.dumps({
                    'status': False,
                    'detail': 'Timeout accessing upstream server: {}'.format(settings.UPSTREAM_HOST)
                })

            resp = HttpResponse(content, status=r.status_code)
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

from collections import OrderedDict
from datetime import datetime
from hashlib import md5
import json
from logging import getLogger
import os
from pprint import pformat

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.staticfiles.templatetags.staticfiles import static
from django.http.response import HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import TemplateView
import pytz
import requests
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
import stripe
from syllable_samples.interface import get_random_sample
from tonerecorder.models import RecordedSyllable

from usermgmt.models import SubscriptionHistory
from webapi.models import RecordingGrade


logger = getLogger(__name__)


def authorized(to_wrap):
    # Wraps a view function, ensuring that the user is authenticated before executing the view.
    # If the user isn't authenticated, returns a json string indicating that.

    def wrapped(request, *args, **kwargs):
        try:
            try:
                request_json_data = json.loads(request.body.decode('utf-8'))
                token = request_json_data['authToken']
            except:
                token = request.POST.get('authToken')

            try:
                expected_token = Token.objects.get(key=token)
            except Token.DoesNotExist:
                msg = 'bad auth token: {}'.format(token)
                resp = JsonResponse({'detail': msg}, status=403)
                return resp

            # Compare utc datetime instances as naive (timezone-unaware) datetimes
            now = datetime.now(tz=pytz.utc)
            token_age_in_hours = (now - expected_token.created).total_seconds() // 3600
            if token_age_in_hours >= 24:
                json_resp = {'status': 'fail', 'msg': 'authentication expired'}
                status = 403
                resp = JsonResponse(json_resp, status=status)
                return resp

            # Everything's good, pass through to the wrapped function
            kwargs['user'] = expected_token.user
            resp = to_wrap(request, *args, **kwargs)
        except Exception as e:
            status = 500
            msg = e.message if hasattr(e, 'message') else pformat(e, indent=4)
            json_resp = {'status': 'fail', 'detail': 'Authorization Exception:\n{}'.format(msg)}
            resp = JsonResponse(json_resp, status=status)

        return resp

    return wrapped


class RandomSyllable(APIView):
    permission_classes = (AllowAny,)

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return APIView.dispatch(self, request, *args, **kwargs)

    @method_decorator(authorized)
    def post(self, request, *args, **kwargs):
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


class StripeTest(TemplateView):
    template_name = 'webapi/stripe_test.html'


class AddMonthSubscription(APIView):
    ''' Adds 1 month to the user's current subscription, or creates a new 1 month subscription if there is
        no current subscription.
    '''
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return View.dispatch(self, request, *args, **kwargs)

    @method_decorator(authorized)
    def post(self, request, *args, **kwargs):
        POST = request.POST
        stripe_token = POST['stripeToken']
        # See your keys here: https://dashboard.stripe.com/account/apikeys
        stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
        month_price = 5.0

        # --- Get latest subscription for user
        user = kwargs['user']

        # Create a charge: this will charge the user's card
        try:
            description = \
                "Purchase of one month ToneTutor subscription for ${}".format(month_price)
            charge = stripe.Charge.create(
                amount=int(month_price * 100),  # Amount in cents
                currency="usd",
                source=stripe_token,
                description=description
            )
            self.success = True

            msg = pformat(charge, indent=4)
            logger.info('Stripe Charge object:\n{}'.format(msg))
        except stripe.error.CardError as e:
            # The card has been declined
            self.success = False
            self.error_msg = 'Stripe CardError: {}'.format(pformat(e, indent=4))
            logger.info(self.error_msg)
        except Exception as e:
            msg = 'Unexpected Error: {}'.format(pformat(e, indent=4))
            self.success = False
            self.error_msg = msg
            logger.critical(msg)


        if self.success is True:
            try:
                latest_subscription = SubscriptionHistory.objects.filter(user=user).order_by('end_date').first()
                if latest_subscription.end_date < datetime.datetime.today() - datetime.timedelta(days=1):
                    latest_subscription = None
            except SubscriptionHistory.DoesNotExist:
                latest_subscription = None

            if latest_subscription is None:
                SubscriptionHistory.objects.create(
                        user=user, begin_date=datetime.datetime.today(),
                        end_date=datetime.datetime.today() + datetime.timedelta(days=31),
                        stripe_confirm=charge['id'], payment_date=datetime.datetime.fromtimestamp(charge['created'])
                )
            else:
                latest_subscription.end_date = latest_subscription.end_date + datetime.timedelta(days=31)
                latest_subscription.save()
            resp = {'subscribed_until': latest_subscription.end_date.strftime('%Y-%m-%d')}
            status_code = 200
        else:
            msg = 'Stripe charge declined: {}'.format(self.error_msg)
            logger.error(msg)
            resp = {'detail': msg}
            status_code = 402

        return JsonResponse(resp, status=status_code)


class AuthenticateUser(APIView):
    ''' Authentication api which takes 3 POST args; username, password, (optional bool, default false) newUser.
        Returns JSON, username, user_id, auth_token on success.  Returns JSON, detail on failure.
    '''
    permission_classes = (AllowAny,)

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return View.dispatch(self, request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')
        new_user = json.loads(request.POST.get('newUser', 'false'))

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
            # Create a new user only if the newUser flag is set and there isn't an existing user.
            if not User.objects.filter(username=username).exists():
                if new_user:
                    User.objects.create_user(username=username, password=password)
                else:
                    # User doesn't exist & new user not indicated.
                    status_code = 400
                    resp = {'detail': 'User "{}" does not exist.'.format(username)}
                    json_resp = json.dumps(resp)
                    http_resp = HttpResponse(json_resp, status=status_code)
                    return http_resp

            user = authenticate(username=username, password=password)

            if user is None:
                status_code = 401
                resp = {
                    'detail': 'Invalid password for {}.'.format(username),
                }
            # If we've got a valid user, update & return an auth token for the user.
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


class GetRecordingToGrade(APIView):

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return View.dispatch(self, request, *args, **kwargs)

    @method_decorator(authorized)
    def post(self, request, *args, **kwargs):
        grading_data = json.loads(request.body.decode('utf-8'))
        listener_id = grading_data['listenerId']
        next_recording = RecordedSyllable.objects.exclude(
            recordinggrade__grader__id=listener_id).exclude(audio_silence_stripped=None).order_by('id').first()

        if next_recording is None:
            json_resp = json.dumps({
                'status': 'complete', 'detail': 'No further recordings to grade now.',
            })
            status_code = 200
        else:
            audio_file_basename = os.path.basename(next_recording.audio_silence_stripped)
            audio_url = os.path.join(settings.MEDIA_URL, settings.SYLLABLE_AUDIO_DIR, audio_file_basename)
            json_resp = json.dumps({
                'status': 'ok', 'recordingId': next_recording.id,
                'pinyin': next_recording.syllable.display, 'audioUrl': audio_url
            })
            status_code = 200

        resp = HttpResponse(json_resp, status=status_code)
        return resp

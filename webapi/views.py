from collections import OrderedDict
from datetime import datetime, timedelta
from hashlib import md5
import json
from logging import getLogger
import os
from pprint import pformat
import pprint
import scipy
from tempfile import NamedTemporaryFile
import traceback

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.staticfiles.templatetags.staticfiles import static
from django.db import transaction
from django.http.response import HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import TemplateView
from hanzi_basics.models import PinyinSyllable
import pytz
import requests
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
import stripe
from syllable_samples.interface import get_random_sample
from tonerecorder.models import RecordedSyllable
from usermgmt.models import SubscriptionHistory

from ttlib.characteristics.interface import generate_all_characteristics
from ttlib.normalization.interface import convert_file_format, normalize_pipeline
from ttlib.recognizer import ToneRecognizer
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
                logger.info('Got authToken from json')
            except Exception as ex:
                token = request.POST.get('authToken')
                logger.info('Got authToken from url-encoded params')

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
                json_resp = {'detail': 'authentication expired'}
                status = 403
                resp = JsonResponse(json_resp, status=status)
                return resp

            # Everything's good, pass through to the wrapped function
            kwargs['user'] = expected_token.user
            request.user = expected_token.user
            try:
                resp = to_wrap(request, *args, **kwargs)
            except Exception as e:
                tb = traceback.format_exc()
                msg = e.message if hasattr(e, 'message') else pformat(e, indent=4)
                logger.error('Unexpected Exception from wrapped function: {}\n{}'.format(msg, tb))
                raise
        except Exception as e:
            status = 500
            msg = e.message if hasattr(e, 'message') else pformat(e, indent=4)
            tb = traceback.format_exc()
            logger.error('Unexpected Authorization Exception: {}\n{}'.format(msg, tb))
            json_resp = {'detail': 'Authorization Exception:\n{}'.format(msg)}
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

        resp = JsonResponse(data)
        return resp


class StripeTest(TemplateView):
    template_name = 'webapi/stripe_test.html'

month_price = 5.0

def add_month_to_subscription(user, stripe_charge=None, itunes_payment_receipt=None):
    latest_subscription = SubscriptionHistory.objects.filter(user=user).order_by('-end_date').first()
    if (latest_subscription is not None and
        latest_subscription.end_date < datetime.date(datetime.today() - timedelta(days=1))):
        latest_subscription = None

    if latest_subscription is None:
        if stripe_charge:
            payment_id = '(stripe) {}'.format(stripe_charge['id'])
            payment_date = datetime.fromtimestamp(stripe_charge['created'])
        elif itunes_payment_receipt:
            payment_id = '(itunes) {}'.format(itunes_payment_receipt.get('transaction_id'))
            payment_date = datetime.fromtimestamp(itunes_payment_receipt.get('purchase_date'))

        SubscriptionHistory.objects.create(
            user=user, begin_date=datetime.today(),
            end_date=datetime.date(datetime.today() + timedelta(days=31)),
            payment_amount=month_price,
            payment_id=payment_id,
            payment_date=payment_date
        )
    else:
        latest_subscription.end_date = latest_subscription.end_date + timedelta(days=31)
        latest_subscription.save()
    resp = {'subscribed_until': latest_subscription.end_date.strftime('%Y-%m-%d')}
    return resp


class ValidateITunesReceipt(APIView):
    ''' Checks an iTunes receipt, and if valid adds 1 month to the user's subscription.
        In: JSON {'receipt-data': <base64-encoded receipt data>}
        Returns:
            (200) JSON {'subscribed_until': <YYYY-MM-DD>
    '''
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return View.dispatch(self, request, *args, **kwargs)

    @method_decorator(authorized)
    def post(self, request, *args, **kwargs):
        testing_service_url = 'https://sandbox.itunes.apple.com/verifyReceipt'
        live_service_url = 'https://buy.itunes.apple.com/verifyReceipt'
        service_url = testing_service_url

        request_args = json.loads(request.body.decode('utf8'))
        receipt_data = request_args['receipt-data']

        service_payload = {'receipt-data': receipt_data}
        itunes_resp = requests.post(service_url, json=service_payload)
        itunes_resp_json = itunes_resp.json()

        if itunes_resp.status_code == 200 and itunes_resp_json['status'] == 0:
            status_code = 200
            json_receipt = itunes_resp_json['receipt']
            receipt_output_friendly = pprint.pformat(json_receipt, indent=2)
            logger.info('Successfully verified itunes receipt:\n {}'.format(receipt_output_friendly))
            resp = add_month_to_subscription(request.user, itunes_payment_receipt=json_receipt)
        elif itunes_resp.status_code == 200:
            status_code = 424
            resp = {'detail': 'itunes validation failure, itunes api status: {}'.format(itunes_resp_json['status'])}
        else:
            status_code = 424
            resp = {'detail': 'Connection to itunes failed with http status code: {}'.format(itunes_resp.status_code)}

        resp = JsonResponse(resp, status=status_code)
        return resp


class AddMonthSubscription(APIView):
    ''' Adds 1 month to the user's current subscription, or creates a new 1 month subscription if there is
        no current subscription.
    '''
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return View.dispatch(self, request, *args, **kwargs)

    @method_decorator(authorized)
    def post(self, request, *args, **kwargs):
        try:
            request_args = json.loads(request.body.decode('utf8'))
            stripe_token = request_args['stripeToken']
            logger.info('Got stripeToken from json payload')
        except:
            POST = request.POST
            stripe_token = POST['stripeToken']
            logger.info('Got stripeToken from url-encoded args')

        # See your keys here: https://dashboard.stripe.com/account/apikeys
        stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
        # One-month subscription price in dollars
        month_price = 5.0

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
            resp = add_month_to_subscription(user, stripe_charge=charge)
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
        logger.info('Authentication requested for user: {} newUser: {}'.format(username, new_user))

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

            logger.error(', '.join(msgs))

            resp = {
                'detail': ', '.join(msgs)
            }
        else:
            # Create a new user only if the newUser flag is set and there isn't an existing user.
            if not User.objects.filter(username=username).exists():
                if new_user:
                    with transaction.atomic():
                        user = User.objects.create_user(username=username, password=password)
                        logger.info('Created new user: {}'.format(username))
                        subscr_begin = datetime.now()
                        subscr_end = subscr_begin + timedelta(days=3)
                        SubscriptionHistory.objects.create(
                            user=user, payment_amount=0, begin_date=subscr_begin, end_date=subscr_end
                        )
                        time_format = '%Y-%m-%dT%H:%M'
                        msg_args = (username, subscr_begin.strftime(time_format), subscr_end.strftime(time_format))
                        msg = 'Added trial subscription of 3 days for {}: {} - {}'.format(*msg_args)
                        logger.info(msg)
                else:
                    # User doesn't exist & new user not indicated.
                    logger.error('User does not exist')
                    status_code = 400
                    resp = {'detail': 'User "{}" does not exist.'.format(username)}
                    http_resp = JsonResponse(resp, status=status_code)
                    return http_resp
            # Return message if newUser is set but the user exists
            else:
                if new_user:
                    logger.info('newUser set for existing username: {}'.format(username))
                    status_code = 400
                    resp = {'detail': 'username "{}" already in use'.format(username)}
                    http_resp = JsonResponse(resp, status=status_code)
                    return http_resp

            logger.info('Attempting authentication')
            user = authenticate(username=username, password=password)
            if user is None:
                logger.info('Authentication failed')
                status_code = 401
                resp = {
                    'detail': 'Invalid password for {}.'.format(username),
                }
            # If we've got a valid user, update & return an auth token for the user.
            else:
                logger.info('Authentication successful, updating auth token')
                token, created = Token.objects.get_or_create(user=user)
                if not created:
                    token.delete()
                    token = Token(user=user)
                    token.save()

                latest_subscription = SubscriptionHistory.objects.filter(user=user).order_by('-end_date').first()
                if latest_subscription is None:
                    logger.info('{} has no subscription records'.format(user.username))
                    subscr_enddate = None
                else:
                    subscr_enddate = latest_subscription.end_date
                    if subscr_enddate < datetime.date(datetime.today() - timedelta(days=1)):
                        subscr_enddate = None

                if subscr_enddate is not None:
                    subscr_enddate_str = subscr_enddate.strftime('%Y-%m-%d')
                else:
                    subscr_enddate_str = 'null'

                status_code = 200
                resp = OrderedDict([
                    ('username', user.username),
                    ('user_id', user.id),
                    ('auth_token', token.key),
                    ('subscr_enddate', subscr_enddate_str),
                ])

        http_resp = JsonResponse(resp, status=status_code)
        return http_resp


class ToneCheck(APIView):
    ''' *brief*: provides a web-api to check the predicted tone of an audio sample.
        *note*: Saves the audio sample for later analsis in model RecordedSyllable.
        *input*: POST with file 'attempt' and values 'extension', 'expected_sound', 'expected_tone',
            'is_native'.
        *return*: JSON-encoded object with 'status' and 'tone' attributes.
            'status' is a boolean indicating if the call was successful.
            'tone' is an integer 1-5 indicating the tone or null indicating that the predictor
                can't tell which tone it is.
            'attempt_url' is a url (without protocol/domain) to an mp3 file of the attempt.
    '''
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return View.dispatch(self, request, *args, **kwargs)

    @method_decorator(authorized)
    def post(self, request, *args, **kwargs):
        try:
            user = kwargs['user']

            attempt = request.FILES['attempt']
            extension = request.POST['extension']
            expected_sound = request.POST['expected_sound']
            expected_tone = request.POST['expected_tone']
            is_native_text = request.POST.get('is_native', 'false')
            is_native = False if is_native_text.lower() == 'false' else True

            s = PinyinSyllable.objects.get(sound=expected_sound, tone=expected_tone)
            rs = RecordedSyllable(native=is_native, user=user, syllable=s, file_extension=extension)
            original_path = rs.create_audio_path('original')

            attempt_data = attempt.read()
            m = md5()
            m.update(attempt_data)
            attempt_md5 = m.hexdigest()
            attempt_claimed_md5 = request.POST.get('attempt_md5', '')

            logger.info('MD5 Claimed: {}, Actual: {}'.format(attempt_claimed_md5, attempt_md5))

            with open(original_path, 'wb') as f:
                f.write(attempt_data)

            rs.audio_original = original_path
            mp3_path = rs.create_audio_path('mp3')
            convert_file_format(original_path, mp3_path)
            rs.audio_mp3 = mp3_path
            try:
                rs.save()
            # When testing, an existing recording may show up again, violating a unique requirement.  It's ok.
            except Exception as ex:
                logger.error('Exception attempting to save attempt audio: {}'.format(ex))
                rs = RecordedSyllable.objects.get(original_md5hex=attempt_md5)

            with open(original_path, 'rb') as original:
                with NamedTemporaryFile(suffix='.wav') as normalized:
                    normalize_pipeline(original_path, normalized.name)
                    sample_rate, wave_data = scipy.io.wavfile.read(normalized.name)
                    # --- Deal with sample that's too short to accurately analyze
                    # minimum length (seconds)
                    min_length = 0.15
                    attempt_length = len(wave_data) / sample_rate
                    logger.info('Attempt length {}{}: {}'.format(
                        expected_sound, expected_tone, attempt_length)
                    )
                    if attempt_length < min_length:
                        msg = 'Attempt shorter than minimum length: {} < {}, skipping analysis'\
                            .format(attempt_length, min_length)
                        logger.info(msg)
                        tone = None
                    else:
                        sample_characteristics = generate_all_characteristics(wave_data, sample_rate)

                        tr = ToneRecognizer()
                        tone = tr.get_tone(sample_characteristics)
                        try:
                            expected_tone_int = int(expected_tone)
                        except:
                            expected_tone_int = expected_tone
                        equal_text = '==' if tone == expected_tone_int else '!='
                        msg = 'Attempt tone ({}) {} expected tone ({})'.format(tone, equal_text, expected_tone)
                        logger.info(msg)

            mp3_filename = os.path.basename(mp3_path)
            attempt_url = settings.AUDIO_PROTOCOL + settings.AUDIO_HOST + settings.AUDIO_PATH + mp3_filename

            result = {
                'status': True,
                'tone': tone,
                'attempt_url': attempt_url,
            }
            resp = JsonResponse(result)
        except Exception as ex:
            tb = traceback.format_exc()
            ex_msg = ex.message if hasattr(ex, 'message') else pformat(ex, indent=4)
            logger.error('Unexpected Exception in ToneCheck.post(): {}\n{}'.format(ex_msg, tb))
            result = {'detail': ex_msg}
            resp = JsonResponse(result)

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

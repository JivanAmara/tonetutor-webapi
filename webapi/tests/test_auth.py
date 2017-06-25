from django.test import TestCase
from django.urls import reverse
import mock
import json
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta

User = get_user_model()

class AuthenticateUserTests(TestCase):

    @mock.patch('webapi.views.SubscriptionHistory.objects.create')
    def test_new_user_is_given_subscription(self, subscription_history_create):
        url = reverse('AuthenticateUser')
        username = 'testuser'
        password = 'testuser'

        json_resp = self.client.post(url, {'username': username, 'password': password, 'newUser': 'true'})
        resp = json.loads(json_resp.content.decode('utf8'))
        user = User.objects.get(id=resp['user_id'])

        msg = 'Auth request failed ({}):\n'.format(json_resp.status_code, resp)
        self.assertEqual(json_resp.status_code, 200, msg)

        subscription_history_create.assert_called_once()
        _sh_args, sh_kwargs = subscription_history_create.call_args

        self.assertEqual(sh_kwargs['user'].username, user.username)
        # Ensure the subscription begin date is approximately now
        self.assertLess(datetime.now() - sh_kwargs['begin_date'], timedelta(seconds=5))
        # Ensure the subscription end date is three days from begin date
        self.assertEqual(sh_kwargs['end_date'] - sh_kwargs['begin_date'], timedelta(days=3))

    def test_existing_user_last_login_updated(self):
        url = reverse('AuthenticateUser')
        username = 'testuser'
        password = 'testuser'

        json_resp = self.client.post(url, {'username': username, 'password': password, 'newUser': 'true'})
        resp = json.loads(json_resp.content.decode('utf8'))
        user = User.objects.get(id=resp['user_id'])
        login0_timestamp = user.last_login

        json_resp = self.client.post(url, {'username': username, 'password': password})
        resp = json.loads(json_resp.content.decode('utf8'))
        user.refresh_from_db()
        login1_timestamp = user.last_login

        self.assertGreater(login1_timestamp, login0_timestamp)

        json_resp = self.client.post(url, {'username': username, 'password': password})
        resp = json.loads(json_resp.content.decode('utf8'))
        user.refresh_from_db()
        login2_timestamp = user.last_login

        self.assertGreater(login2_timestamp, login1_timestamp)

import os
from tonetutor_webapi.settings import *

DEBUG = True
LOG_FILEPATH = os.path.join(os.path.dirname(__file__), os.pardir, 'debug.log')

UPSTREAM_PROTOCOL = os.environ.get('UPSTREAM_PROTOCOL', 'http://')
UPSTREAM_HOST = os.environ.get('UPSTREAM_HOST', '192.168.1.100:8000')

# This project needs to share the database with the upstream server for authentication purposes.
# They use a common auth.User model and restframework.Token model.
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, os.pardir, 'tonetutor', 'db.sqlite3'),
    }
}

LOGGING['handlers']['file']['filename'] = LOG_FILEPATH

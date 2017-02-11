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
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'webvdc',  # Or path to database file if using sqlite3.
        'USER': 'webvdc',  # Not used with sqlite3.
        'PASSWORD': 'webvdc',  # Not used with sqlite3.
        'HOST': 'localhost',  # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '',  # Set to empty string for default. Not used with sqlite3.
    }
}

LOGGING['handlers']['file']['filename'] = LOG_FILEPATH

MEDIA_ROOT = '/mnt/data-volume/tonetutor-media/'
MEDIA_URL = '/media/'
SYLLABLE_AUDIO_DIR = 'audio-files'

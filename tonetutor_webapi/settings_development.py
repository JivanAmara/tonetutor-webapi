from tonetutor_webapi.settings import *

DEBUG = True

UPSTREAM_PROTOCOL = 'http://'
UPSTREAM_HOST = '192.168.1.100:8000'

# This project needs to share the database with the upstream server for authentication purposes.
# They use a common auth.User model and restframework.Token model.
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, os.pardir, 'tonetutor', 'db.sqlite3'),
    }
}

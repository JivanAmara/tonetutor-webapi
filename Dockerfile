FROM phusion-updated-apt:latest

RUN apt-get install -y python3-pip
RUN pip3 install --upgrade pip

RUN apt-get install -y nginx

# --- Copy pip package tarballs into image
RUN mkdir /tonetutor_webapi
COPY docker /tonetutor_webapi/docker/

# --- Install system-level depedencies
# Needed by pip install of psycopg2
RUN apt-get install -y libpq-dev

# Needed by ttlib
RUN apt-get install -y normalize-audio
RUN apt-get install -y libav-tools
RUN apt-get install -y python3-scipy
RUN apt-get install -y libtaglib-ocaml-dev
RUN apt-get install -y python3-tk
RUN apt-get install -y libsnack2
WORKDIR /tonetutor_webapi/docker/dependencies/snack_2.2.10/python/
RUN python3 setup.py install
WORKDIR /

# Needed to support running package tkSnack without X-Windows (used by ttlib)
RUN apt-get install -y xvfb

# --- Python app dependencies
COPY tonetutor_webapi/requirements.txt /tonetutor_webapi/tonetutor_webapi/requirements.txt
COPY docker/dependencies /docker/dependencies
RUN pip3 install -r /tonetutor_webapi/tonetutor_webapi/requirements.txt

# --- Copy Django code & configuration into image
COPY tonetutor_webapi /tonetutor_webapi/tonetutor_webapi/
COPY webapi /tonetutor_webapi/webapi/
COPY manage.py /tonetutor_webapi/

# --- Copy remaining docker folders into image
COPY docker/service /docker/service
COPY docker/nginx /docker/nginx

# --- Set up nginx
RUN rm /etc/nginx/sites-enabled/default
RUN cp /docker/nginx/tonetutor_webapi.nginx /etc/nginx/sites-available/
RUN ln -s /etc/nginx/sites-available/tonetutor_webapi.nginx /etc/nginx/sites-enabled

# --- Collect Django static files
# (This should match settings.STATIC_ROOT)
RUN mkdir /tonetutor_webapi-static
# Set SECRET_KEY which is needed to run to a dummpy value which won't be used for this command.
RUN SECRET_KEY='tempsecretkey' python3 /tonetutor_webapi/manage.py collectstatic --noinput

# --- Scripts to run at container start
# Unfortunately this is preventing startup.  Migrations will have to be done manually.
#COPY docker/my_init.d/migrate_django_db.sh /etc/my_init.d/

# --- Services to start at container start
COPY docker/service /etc/service

# Adds remote path mapping via env vars to pydevd to support remote debugging.
COPY ./docker/pydevd_path_mapping_snippet.py /tonetutor_webapi/
RUN bash -c '\
    export SNIPPET=`cat /tonetutor_webapi/pydevd_path_mapping_snippet.py`;\
    export PYDEVD_FILE_UTILS=/usr/local/lib/python3.4/dist-packages/pydevd_file_utils.py;\
    perl -0777 -i -pe "s/PATHS_FROM_ECLIPSE_TO_PYTHON = \[\]/$SNIPPET/" $PYDEVD_FILE_UTILS \
'

# Run With:
# docker run --name <container-name> -e SECRET_KEY=<site-secret-key> -e DB_PASS=<db-pass> -e STRIPE_SECRET_KEY=<secret-key> -dit -p <host_port>:80 -v /mnt/data-volume/tonetutor-media/:/mnt/data-volume/tonetutor-media/ --add-host=database-host:<host-ip> <image>
# - Optional -e AUDIO_HOST (www.mandarintt.com) is the host serving audio files. Setting this overrides default in settings file.
# - Optional -e AUDIO_PROTOCOL (http://) can be set to change from default in settings file.
# - Optional -e AUDIO_PATH (/audio/) can be set to change from default in settings file.
# - Optional -e DEBUG=True will run using the production settings file but with DEBUG=True
# Enter the container and run migrations 'xvfb-run -a python3 /tonetutor_webapi/manage.py migrate --noinput'

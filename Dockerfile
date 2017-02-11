FROM phusion/baseimage

RUN apt-get update
RUN apt-get install -y python3-pip
RUN pip3 install --upgrade pip

RUN apt-get install -y nginx

# --- Copy pip package tarballs into image
RUN mkdir /tonetutor_webapi
COPY docker /tonetutor_webapi/docker/

# --- Install system-level depedencies
# Needed by pip install of psycopg2
RUN apt-get install -y libpq-dev

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

# Run With:
# docker run --name <container-name> -e SECRET_KEY=<site-secret-key> -e DB_PASS=<db-pass> -e UPSTREAM_HOST=<upstream-host> -dit -p <host_port>:80 -v /mnt/data-volume/tonetutor-media/audio-files/:/tonetutor-media/tonetutor-audio-files/ --add-host=database-host:<host-ip> <image>
# - Optional -e UPSTREAM_HOST is the host doing tone checks. Setting this overrides default in settings file.
# - Optional -e UPSTREAM_PROTOCOL can be set to change from default in settings file.
# - Optional -e DEBUG=True will run using the production settings file but with DEBUG=True
# Enter the container and run migrations 'python3 /tonetutor_webapi/manage.py migrate --noinput'

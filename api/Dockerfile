FROM quay.io/blockstack/blockstack-core:develop-configure-mongo

WORKDIR /src/blockstack/api

COPY deployment/config.py config.py
COPY deployment/blockstack_api.ini deployment/blockstack_api.ini

RUN pip install -r requirements.txt
RUN pip install uwsgi

RUN mkdir /var/blockstack-search

CMD ["/usr/local/bin/uwsgi", "--ini", "deployment/blockstack_api.ini"]

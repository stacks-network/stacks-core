# need to run this from the git root directory
# docker build -f api/search/Dockerfile . 
FROM python:2.7-alpine

WORKDIR /src/blockstack

# Install dependancies from apt
RUN apk update
RUN apk add libffi-dev openssl-dev build-base linux-headers musl musl-dev musl-utils gcc python python-dev py-pip lsof curl make bash sqlite tini

# run init
ENTRYPOINT ["/sbin/tini", "--"]

# Upgrade pip and install pyparsing
RUN pip install --upgrade pip && pip install pyparsing uwsgi

# Copy all files from the repo into the container
COPY . .

# install Blockstack from source
RUN python ./setup.py build && python ./setup.py install

# install ancillary requirements
RUN pip install -r api/requirements.txt

# Install Blockstack from source
RUN pip install . --upgrade

# Create data dir
RUN mkdir /var/blockstack-search

# Work out of the /api dir
WORKDIR /src/blockstack/api

# Add crontab file in the cron directory
COPY api/deployment/crontab /var/spool/cron/crontabs/root

# Copy fixtures
COPY api/search/fixtures/blockchain_data.json /var/blockstack-search/blockchain_data.json
COPY api/search/fixtures/profile_data.slice.json /var/blockstack-search/profile_data.json

# Give execution rights on the cron job
RUN chmod 0600 /var/spool/cron/crontabs/root

# install fixtures and run cron
CMD ["crond","-f","-d","8"]

FROM python:2.7-alpine

WORKDIR /src/blockstack

# Install dependancies from apt
RUN apk update
RUN apk add libffi-dev openssl-dev build-base linux-headers musl musl-dev musl-utils gcc python python-dev py-pip lsof curl make bash

# Copy all files from the repo into the container
COPY . .

# # Upgrade pip and install pyparsing
RUN pip install --upgrade pip && pip install pyparsing uwsgi
RUN pip install -r api/requirements.txt

# Install Blockstack from source
RUN pip install . --upgrade

# Create data dir
RUN mkdir /var/blockstack-search

# Work out of the /api dir
WORKDIR /src/blockstack/api

# Add crontab file in the cron directory
COPY api/deployment/crontab /var/spool/cron/crontabs/root
# COPY api/deployment/client.ini /root/.blockstack/client.ini

# Give execution rights on the cron job
RUN chmod 0600 /var/spool/cron/crontabs/root

# Cron needs to be in the foreground
CMD ["crond", "-f", "-d", "8"]

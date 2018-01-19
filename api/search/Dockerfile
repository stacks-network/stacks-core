FROM ubuntu:xenial

WORKDIR /src/blockstack

# Install dependancies from apt
RUN apt-get -y update
RUN apt-get install -y python-pip python-dev libssl-dev libffi-dev rng-tools libgmp3-dev lsof curl

RUN apt-get install -y cron

# Copy all files from the repo into the container
COPY . .

# Upgrade pip and install pyparsing
RUN pip install --upgrade pip && pip install pyparsing uwsgi
RUN pip install -r api/requirements.txt

# Install Blockstack from source
RUN pip install . --upgrade

# Create data dir
RUN mkdir /var/blockstack-search

# Work out of the /api dir
WORKDIR /src/blockstack/api

# Add crontab file in the cron directory
COPY api/deployment/crontab /etc/cron.d/search-index-cron
COPY api/deployment/client.ini /root/.blockstack/client.ini

# Give execution rights on the cron job
RUN chmod 0644 /etc/cron.d/search-index-cron

# Create the log file to be able to run tail
RUN touch /var/log/cron.log

# cron on startup
CMD python -m api.search.basic_index --refresh && cron && tail -f /var/log/cron.log

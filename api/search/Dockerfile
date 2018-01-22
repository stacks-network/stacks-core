FROM ubuntu:xenial

WORKDIR /src/blockstack

# Install dependancies from apt
RUN apt-get -y update
RUN apt-get install -y python-pip python-dev libssl-dev libffi-dev rng-tools libgmp3-dev lsof curl cron

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
COPY api/deployment/crontab /var/spool/cron/crontabs/root
COPY api/deployment/client.ini /root/.blockstack/client.ini

# Give execution rights on the cron job
RUN chmod 0600 /var/spool/cron/crontabs/root

# Cron is our entry point
ENTRYPOINT "crond"

# Cron needs to be in the foreground
CMD ["-f", "-d", "8"]

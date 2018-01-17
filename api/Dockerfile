FROM ubuntu:xenial

WORKDIR /src/blockstack

# Install dependancies from apt
RUN apt-get -y update
RUN apt-get install -y python-pip python-dev libssl-dev libffi-dev rng-tools libgmp3-dev lsof curl

# Install Node
RUN curl -sL https://deb.nodesource.com/setup_8.x | bash -
RUN apt-get install -y nodejs

# Install aglio to build docs
RUN npm -g install aglio --unsafe

# Copy all files from the repo into the container
COPY . .

# Upgrade pip and install pyparsing
RUN pip install --upgrade pip && pip install pyparsing uwsgi
RUN pip install -r api/requirements.txt

# Install Blockstack from source
RUN pip install . --upgrade

# Create data dir
RUN mkdir /var/blockstack-search

# Build Documentation
RUN ./build_docs.sh public_api

# Work out of the /api dir
WORKDIR /src/blockstack/api

# Start the uwsgi server
CMD ["/usr/local/bin/uwsgi", "--ini", "deployment/blockstack_api.ini"]

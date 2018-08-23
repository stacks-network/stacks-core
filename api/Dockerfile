# run from git root
# docker build -f api/Dockerfile .
FROM ubuntu:xenial

EXPOSE 3000

# Install dependancies from apt
RUN apt-get -y update
RUN apt-get install -y python-pip python-dev libssl-dev libffi-dev rng-tools libgmp3-dev lsof curl sqlite3 gnupg2

# add a minimal pid 1
ENV TINI_VERSION v0.18.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini.asc /tini.asc
RUN gpg2 --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7 \
 && gpg2 --verify /tini.asc

RUN chmod +x /tini
ENTRYPOINT ["/tini", "--"]

# set up API server
WORKDIR /src/blockstack

# Install Node
RUN curl -sL https://deb.nodesource.com/setup_8.x | bash -
RUN apt-get install -y nodejs

# Install aglio to build docs
RUN npm -g install aglio --unsafe

# Copy all files from the repo into the container
COPY . .

# Upgrade pip and install pyparsing
RUN pip install --upgrade pip
RUN pip install pyparsing uwsgi

# install Blockstack from source
RUN python ./setup.py build && python ./setup.py install

# install ancillary deps
RUN pip install -r api/requirements.txt

# Create data dir
RUN mkdir /var/blockstack-search

# Build Documentation
RUN ./build_docs.sh public_api

# Work out of the /api dir
WORKDIR /src/blockstack/api

# Start the uwsgi server
CMD ["/usr/local/bin/uwsgi", "--ini", "deployment/blockstack_api.ini"]

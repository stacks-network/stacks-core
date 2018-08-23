FROM ubuntu:xenial

# Install dependencies from apt
RUN apt-get -y update && \
    apt-get install -y python-pip python-dev libssl-dev libffi-dev rng-tools libgmp3-dev lsof sqlite3 gnupg2

# add a minimal pid 1
ENV TINI_VERSION v0.18.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini.asc /tini.asc
RUN gpg2 --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7 \
 && gpg2 --verify /tini.asc

RUN chmod +x /tini
ENTRYPOINT ["/tini", "--"]

WORKDIR /src/blockstack

# Copy all files from the repo into the container
COPY . .

# Upgrade pip and install pyparsing
RUN pip install pyparsing

# Install Blockstack from source
RUN python ./setup.py build && python ./setup.py install

# Boot up
CMD ["bash", "api/deployment/boot-docker.sh"]

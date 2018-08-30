FROM ubuntu:bionic

# Install dependencies from apt
RUN apt-get -y update && \
    apt-get install -y python-pip rng-tools libgmp3-dev lsof sqlite3 gnupg2

# add a minimal pid 1
ENV TINI_VERSION v0.18.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini.asc /tini.asc

# Check signed tini binary
ENV GPG_KEY_SERVERS_LIST ha.pool.sks-keyservers.net \
                         hkp://p80.pool.sks-keyservers.net:80 \
                         keyserver.ubuntu.com \
                         hkp://keyserver.ubuntu.com:80 \
                         pgp.mit.edu

RUN for server in $GPG_KEY_SERVERS_LIST ; do \
      gpg --keyserver "$server" --recv-keys 595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7 && break || : ; \
  done
RUN gpg2 --verify /tini.asc

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

FROM ubuntu:bionic
WORKDIR /src/blockstack


# Install dependencies from apt
RUN apt-get -y update && \
    apt-get install -y python-pip python-dev libssl-dev libffi-dev \
    rng-tools libgmp3-dev lsof wget curl apt-utils git gnupg sqlite3 \
    software-properties-common

# We need bitcoind
RUN add-apt-repository ppa:bitcoin/bitcoin
RUN apt-get -y update
RUN apt-get install -y bitcoind

# Add standard username and password
RUN mkdir ~/.bitcoin
RUN echo "rpcuser=blockstack\nrpcpassword=blockstacksystem\nrpcbind=0.0.0.0\nrpcallowip=0.0.0.0/0\n" > ~/.bitcoin/bitcoin.conf

# Install node
RUN curl -sL https://deb.nodesource.com/setup_8.x | bash -
RUN apt-get update && apt-get install -y nodejs

# Install node apps

# Blockstack.js
ADD https://api.github.com/repos/blockstack/blockstack.js/git/refs/heads/master blockstackjs-version.json
RUN cd /src/ && git clone https://github.com/blockstack/blockstack.js.git
RUN cd /src/blockstack.js && npm i && npm run build && npm i . -g

# Transaction broadcaster
ADD https://api.github.com/repos/blockstack/transaction-broadcaster/git/refs/heads/master broadcaster-version.json
RUN cd /src/ && git clone https://github.com/blockstack/transaction-broadcaster.git
RUN cd /src/transaction-broadcaster && npm i && npm run build && npm i . -g

# CLI
ADD https://api.github.com/repos/blockstack/cli-blockstack/git/refs/heads/master cli-version.json
RUN cd /src/ && git clone https://github.com/blockstack/cli-blockstack.git
RUN cd /src/cli-blockstack && npm i && npm ln blockstack && npm run build && npm i . -g

# Gaia hub

ADD https://api.github.com/repos/blockstack/gaia/git/refs/heads/master gaia-hub-version.json
RUN cd /src/ && git clone https://github.com/blockstack/gaia.git
RUN cd /src/gaia/hub && npm i && npm run build && npm i . -g

# Subdomain registrar

ADD https://api.github.com/repos/blockstack/subdomain-registrar/git/refs/heads/master registrar-version.json
RUN cd /src/ && git clone https://github.com/blockstack/subdomain-registrar
RUN cd /src/subdomain-registrar && npm i && npm run build && npm i . -g


# Copy all files from the repo into the container
COPY . .

# Upgrade pip and install pyparsing
RUN pip install pyparsing

# Install Blockstack from source
RUN pip install . --upgrade
RUN pip install ./integration_tests --upgrade

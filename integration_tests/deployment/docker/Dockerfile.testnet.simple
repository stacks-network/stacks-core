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
ADD https://api.github.com/repos/blockstack/blockstack.js/git/refs/heads/feature/stacks-transactions+aaron blockstackjs-version.json
RUN cd /src/ && git clone https://github.com/blockstack/blockstack.js.git
RUN cd /src/blockstack.js && git checkout feature/stacks-transactions+aaron
RUN cd /src/blockstack.js && npm i && npm run build && npm i . -g

# Transaction broadcaster
ADD https://api.github.com/repos/blockstack/transaction-broadcaster/git/refs/heads/master broadcaster-version.json
RUN cd /src/ && git clone https://github.com/blockstack/transaction-broadcaster.git
RUN cd /src/transaction-broadcaster && npm i && npm run build && npm i . -g

# CLI
ADD https://api.github.com/repos/kantai/cli-blockstack/git/refs/heads/master cli-version.json
RUN cd /src/ && git clone https://github.com/kantai/cli-blockstack.git
RUN cd /src/cli-blockstack && git checkout master
RUN cat /src/cli-blockstack/package.json | grep -v '"blockstack": "^19' > /tmp/package.json
RUN mv /tmp/package.json /src/cli-blockstack/package.json
RUN cd /src/cli-blockstack && npm i && npm ln blockstack && npm run build && npm i . -g

# Virtualchain
ADD https://api.github.com/repos/blockstack/virtualchain/git/refs/heads/develop vc-version.json
RUN cd /src/ && git clone https://github.com/blockstack/virtualchain.git
RUN cd /src/virtualchain && git checkout develop
RUN cd /src/virtualchain && pip install . --upgrade

# Copy all files from the repo into the container
COPY . .

# Upgrade pip and install pyparsing
RUN pip install pyparsing

# Install Blockstack from source
RUN pip install . --upgrade
RUN pip install ./integration_tests --upgrade

RUN cd /src/blockstack/testnet && python index.html.py > index.html

CMD /src/blockstack/testnet/testnet_simple.sh

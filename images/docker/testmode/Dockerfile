FROM docker/whalesay:latest

# Install Blockstack Core
RUN sudo apt-get update && sudo apt-get install -y build-essential python-pip git-core python-dev libssl-dev libffi-dev rng-tools libgmp3-dev lsof
RUN sudo pip install pip --upgrade
RUN sudo pip install blockstack --upgrade

# Install bitcoind (needed for regtest mode)
RUN useradd -r bitcoin

ENV GOSU_VERSION=1.9

RUN apt-get update -y \
  && apt-get install -y curl \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN gpg --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4

RUN curl -o /usr/local/bin/gosu -fSL https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-$(dpkg --print-architecture) \
    && curl -o /usr/local/bin/gosu.asc -fSL https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-$(dpkg --print-architecture).asc \
    && gpg --verify /usr/local/bin/gosu.asc \
    && rm /usr/local/bin/gosu.asc \
    && chmod +x /usr/local/bin/gosu

ENV BITCOIN_VERSION=0.16.1
ENV BITCOIN_DATA=/home/bitcoin/.bitcoin \
  PATH=/opt/bitcoin-${BITCOIN_VERSION}/bin:$PATH

RUN curl -SL https://bitcoin.org/laanwj-releases.asc | gpg --import \
  && curl -SLO https://bitcoin.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS.asc \
  && curl -SLO https://bitcoin.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}${BITCOIN_BRANCH}-x86_64-linux-gnu.tar.gz \
  && gpg --verify SHA256SUMS.asc \
  && grep " bitcoin-${BITCOIN_VERSION}${BITCOIN_BRANCH}-x86_64-linux-gnu.tar.gz\$" SHA256SUMS.asc | sha256sum -c - \
  && tar -xzf bitcoin-${BITCOIN_VERSION}${BITCOIN_BRANCH}-x86_64-linux-gnu.tar.gz -C /opt \
  && rm bitcoin-${BITCOIN_VERSION}${BITCOIN_BRANCH}-x86_64-linux-gnu.tar.gz SHA256SUMS.asc

VOLUME ["/home/bitcoin/.bitcoin"]

RUN mkdir -p /usr/local/blockstack-core
RUN git clone https://github.com/blockstack/blockstack-core /usr/local/blockstack-core

WORKDIR /usr/local/blockstack-core

# Install the test framework
RUN cd integration-tests/
RUN ./setup.py build && sudo ./setup.py install
 
EXPOSE 6264
EXPOSE 6270

# Run one of the scenarios in "interactive" mode to populate the blockchain, 
# with 10-second block times once it finishes
CMD blockstack-test-scenario --interactive 10 blockstack_integration_tests.scenarios.name_pre_reg_stacks

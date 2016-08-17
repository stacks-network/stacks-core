############################################################
# Dockerfile to build namecoind
# Based on Ubuntu
############################################################

# Set the base-image
# the base-image already has a copy of the blockchain
FROM digitalpassport/blockchain

# File Author / Maintainer
MAINTAINER Muneeb Ali (@muneeb)

################## BEGIN INSTALLATION ######################

RUN apt-get update

# Create the default directory
RUN mkdir -p /srv

# Install Namecoind
RUN apt-get install -y \
    build-essential \
    libssl-dev \
    libboost-all-dev \
    libgtk2.0-dev \
    git

# Assuming older version of libdb was already setup
RUN apt-get install -y --force-yes \
    libdb4.8-dev \
    libdb4.8++-dev

# Create the default service directory
RUN git clone https://github.com/namecoin/namecoin.git /srv/namecoin

# Compile
WORKDIR /srv/namecoin/src
RUN make namecoind

##################### INSTALLATION END #####################

# Expose the default http and https port
EXPOSE 8332

# Set default entry point
ENTRYPOINT /srv/namecoin/src/namecoind --daemon
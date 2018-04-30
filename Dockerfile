FROM ubuntu:xenial

WORKDIR /src/blockstack

# Install dependencies from apt
RUN apt-get -y update && \
    apt-get install -y python-pip python-dev libssl-dev libffi-dev rng-tools libgmp3-dev lsof

# Copy all files from the repo into the container
COPY . .

# Upgrade pip and install pyparsing
RUN pip install pyparsing

# Install Blockstack from source
RUN pip install .

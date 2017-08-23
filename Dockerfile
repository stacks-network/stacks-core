# Run in Ubuntu
FROM ubuntu:xenial

# Create directory for build
RUN mkdir -p /src/blockstack

# Copy in source files
COPY . /src/blockstack
WORKDIR /src/blockstack

# Install Dependancies
RUN apt-get update && apt-get install -y python-pip python-dev build-essential apt-utils libssl-dev libffi-dev rng-tools libgmp3-dev sudo software-properties-common sqlite3 lsof
RUN pip2 install --upgrade pip
RUN pip2 install --upgrade virtualenv

# Build Blockstack
RUN pip2 install . --upgrade
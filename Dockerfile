# Run in Ubuntu
FROM ubuntu:xenial

# Create directory for build
RUN mkdir -p /src/blockstack

# Copy in source files
COPY . /src/blockstack
WORKDIR /src/blockstack

# Install Dependancies
RUN apt-get update && apt-get install -y python-pip python-dev build-essential apt-utils libssl-dev libffi-dev rng-tools libgmp3-dev sudo software-properties-common sqlite3 lsof curl wget

# Lets add blockstack-browser to the mix
RUN wget -qO - https://raw.githubusercontent.com/blockstack/packaging/master/repo-key.pub | apt-key add -
RUN echo 'deb http://packages.blockstack.com/repositories/ubuntu/ xenial main' > /etc/apt/sources.list.d/blockstack.list
RUN curl -sL https://deb.nodesource.com/setup_8.x | bash -
RUN apt-get update
RUN apt-get install -y blockstack-browser

RUN pip2 install --upgrade pip
RUN pip2 install --upgrade virtualenv

# Build Blockstack
RUN pip2 install . --upgrade

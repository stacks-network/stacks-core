# Run in Ubuntu
FROM ubuntu:xenial

# Update apt and install wget
RUN apt update && apt install -y wget

# Add blockstack apt repo
RUN wget -qO - https://raw.githubusercontent.com/blockstack/packaging/master/repo-key.pub | apt-key add -
RUN echo 'deb http://packages.blockstack.com/repositories/ubuntu/ xenial main' > /etc/apt/sources.list.d/blockstack.list

# Install blockstack
RUN apt update && apt install -y blockstack


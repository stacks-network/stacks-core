############################################################
# Dockerfile to build openname-resolver
# Based on Ubuntu
############################################################

# Set the base image to Ubuntu
FROM ubuntu:14.04
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# File Author / Maintainer
MAINTAINER Muneeb Ali (@muneeb)

# Update the repository sources list
RUN apt-get dist-upgrade

################## BEGIN INSTALLATION ######################

# Add the package verification key
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10

# For installing older version of libdb
RUN echo 'deb http://ftp.us.debian.org/debian/ oldstable main' >> /etc/apt/sources.list

# Update the repository sources list once more
RUN apt-get update
RUN apt-get -y upgrade

# Setup conf
ADD namecoin_config.tar.gz /root
RUN chmod 700 /root/.namecoin
# RUN echo -e "rpcuser=opennamesystem\nrpcpassword=opennamesystem" > /root/.namecoin/namecoin.conf
RUN chmod 600 /root/.namecoin/namecoin.conf

#on ubuntu namecoind writes to / instead of /root, symlink it
RUN ln -s /root/.namecoin /.namecoin

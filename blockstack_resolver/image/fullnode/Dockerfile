############################################################
# Dockerfile to build openname-resolver
# Based on Ubuntu
############################################################

# Set the base image to Ubuntu
FROM ubuntu

# File Author / Maintainer
MAINTAINER Muneeb Ali (@muneeb)

# Update the repository sources list
RUN apt-get dist-upgrade

################## BEGIN INSTALLATION ######################

# Add the package verification key
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10

# Update the repository sources list once more
RUN apt-get update
RUN apt-get -y upgrade

# Install Apache2
RUN apt-get install -y \
    apache2 \
    apache2-utils \
    libapache2-mod-wsgi \
    git \
    python-pip

# Install Memcached
RUN apt-get install -y python-dev \
    libmemcached-dev \
    zlib1g-dev \
    memcached

# Create the default directory
RUN mkdir -p /srv

# Clone the app from github and install packages
RUN git clone https://github.com/openname/openname-resolver.git /srv/openname-resolver

# Uncomment below if using a local tar.gz file
#ADD openname-resolver.tar.gz /srv/

WORKDIR /srv/openname-resolver
RUN chmod 755 /srv/openname-resolver/run.sh
RUN pip install -r requirements.txt

# Copy the Apache config files
RUN cp -f /srv/openname-resolver/apache/config/default.conf /etc/apache2/sites-available/000-default.conf
RUN cp -f /srv/openname-resolver/apache/config/wsgi.conf /etc/apache2/conf-enabled

RUN cp -f /srv/openname-resolver/image/fullnode/run.sh /srv/openname-resolver/

# Install Namecoind
RUN apt-get install -y \
    build-essential \
    libssl-dev \
    libboost-all-dev \
    libgtk2.0-dev \
    git

# For installing older version of libdb
RUN echo 'deb http://ftp.us.debian.org/debian/ oldstable main' >> /etc/apt/sources.list
RUN apt-get update

RUN apt-get install -y --force-yes \
    libdb4.8-dev \
    libdb4.8++-dev

# Create the default service directory
RUN git clone https://github.com/namecoin/namecoin.git /srv/namecoin

# Compile
WORKDIR /srv/namecoin/src
RUN make namecoind

# Setup conf
ADD namecoin_config.tar.gz /root
RUN chmod 700 /root/.namecoin
# RUN echo -e "rpcuser=opennamesystem\nrpcpassword=opennamesystem" > /root/.namecoin/namecoin.conf
RUN chmod 600 /root/.namecoin/namecoin.conf

#on ubuntu namecoind writes to / instead of /root, symlink it
RUN ln -s /root/.namecoin /.namecoin

##################### INSTALLATION END #####################

# Expose the default port
EXPOSE 80

# Set default entry point
ENTRYPOINT /srv/openname-resolver/run.sh
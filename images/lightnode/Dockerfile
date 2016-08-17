############################################################
# Dockerfile to build resolver
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
RUN git clone https://github.com/openname/resolver.git /srv/resolver

WORKDIR /srv/resolver
RUN chmod 755 /srv/resolver/run.sh
RUN pip install -r requirements.txt

# Copy the Apache config files
RUN cp -f /srv/resolver/apache/config/default.conf /etc/apache2/sites-available/000-default.conf
RUN cp -f /srv/resolver/apache/config/wsgi.conf /etc/apache2/conf-enabled

RUN cp -f /srv/resolver/image/lightnode/run.sh /srv/resolver/

# Set env variables here (can also use config_local.py file or pass them to Docker with -e)
#ENV NAMECOIND_SERVER <your server> 
#ENV NAMECOIND_PORT <your port>
#ENV NAMECOIND_USER <fill this>
#ENV NAMECOIND_PASSWD <fill this>
#ENV API_USERNAME <fill this>
#ENV API_PASSWORD <fill this>

##################### INSTALLATION END #####################

# Expose the default port
EXPOSE 80

# Set default entry point
ENTRYPOINT /srv/resolver/run.sh
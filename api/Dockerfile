FROM quay.io/blockstack/blockstack-core:develop-configure-mongo

WORKDIR /src/blockstack

# Install Apt Dependancies
RUN apt-get update && apt-get install -y curl

# Install Node
RUN curl -sL https://deb.nodesource.com/setup_6.x | bash -
RUN apt-get install -y nodejs

# Install aglio to build docs
RUN npm -g install aglio --unsafe

# Install pip requirements and uwsgi server
RUN pip install -r api/requirements.txt
RUN pip install uwsgi

# Create data dir
RUN mkdir /var/blockstack-search

WORKDIR /src/blockstack/api
COPY . .
WORKDIR /src/blockstack

# Rebuild Python
RUN pip install . --upgrade

# Build Documentation
RUN ./build_docs.sh public_api

# Work out of the /api dir
WORKDIR /src/blockstack/api

# Start the uwsgi server
CMD ["/usr/local/bin/uwsgi", "--ini", "deployment/blockstack_api.ini"]

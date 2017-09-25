FROM docker/whalesay:latest

RUN sudo apt-get update && sudo apt-get install -y build-essential python-pip git-core python-dev libssl-dev libffi-dev rng-tools libgmp3-dev lsof
RUN sudo pip install pip --upgrade
RUN sudo pip install blockstack --upgrade

RUN mkdir -p /usr/local/blockstack-core
RUN git clone https://github.com/blockstack/blockstack-core /usr/local/blockstack-core

WORKDIR /usr/local/blockstack-core

RUN git fetch origin
RUN git checkout -b api origin/api
RUN sudo apt-get install -y libmemcached-dev zlib1g-dev
RUN pip install --upgrade -r api/requirements.txt

EXPOSE 5000

CMD bin/blockstack-api
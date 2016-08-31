FROM debian:jessie

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y update && apt-get -y install python2.7 python-pip python-setuptools python-dev git-core build-essential
WORKDIR  /tmp
RUN git clone https://github.com/openname/blockstack.git
RUN easy_install -U pip
RUN cd blockstack && pip install --upgrade -r requirements.txt
RUN pip install blockstack
WORKDIR /root
CMD blockstackd start

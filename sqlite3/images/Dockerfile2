FROM ubuntu:14.04

RUN apt-get -y update && apt-get -y install python-setuptools python-dev git-core build-essential
RUN easy_install -U pip

RUN mkdir -p /root/blockstack
RUN git clone https://github.com/namesystem/blockstack.git /root/blockstack

WORKDIR /root/blockstack
RUN pip install --upgrade -r requirements.txt
RUN pip install blockstack

EXPOSE 6264

CMD blockstackd start

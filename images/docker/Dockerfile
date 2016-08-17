FROM ubuntu:14.04

RUN apt-get -y update && apt-get -y install python-setuptools python-dev git-core build-essential libssl-dev libffi-dev
RUN easy_install -U pip

RUN mkdir -p /usr/local/blockstack-server
RUN git clone https://github.com/blockstack/blockstack-server /usr/local/blockstack-server
WORKDIR /usr/local/blockstack-server

#Test using a particular branch
#RUN git checkout release-candidate

RUN pip install --upgrade -r requirements.txt
RUN pip install blockstack

EXPOSE 6264

ADD blockstore.ini /root/.blockstore/blockstore.ini

CMD blockstack-server start

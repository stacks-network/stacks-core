FROM ubuntu:14.04

RUN apt-get -y update && apt-get -y install python-setuptools python-dev git-core build-essential
RUN easy_install -U pip

RUN mkdir -p /root/blockstore
RUN git clone https://github.com/namesystem/blockstore.git /root/blockstore

WORKDIR /root/blockstore
RUN pip install --upgrade -r requirements.txt
RUN pip install blockstore

EXPOSE 6264

CMD blockstored start

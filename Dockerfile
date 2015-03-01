FROM debian:jessie

RUN apt-get -y update && apt-get -y install python2.7 python-pip python-setuptools python-dev git-core build-essential
WORKDIR  /tmp
RUN git clone https://github.com/openname/blockstore.git
RUN easy_install -U pip
RUN cd blockstore && pip install --upgrade -r requirements.txt
RUN pip install blockstore
CMD blockstored start

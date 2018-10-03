FROM ubuntu:18.04

RUN apt-get update && apt-get install -y build-essential python-pip git-core python-dev libssl-dev libffi-dev rng-tools libgmp3-dev lsof
RUN pip install pip --upgrade
RUN pip install blockstack --upgrade

EXPOSE 6264

CMD blockstack-core --debug start

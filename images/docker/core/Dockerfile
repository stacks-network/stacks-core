FROM docker/whalesay:latest

RUN sudo apt-get update && sudo apt-get install -y build-essential python-pip git-core python-dev libssl-dev libffi-dev rng-tools libgmp3-dev lsof
RUN sudo pip install pip --upgrade
RUN sudo pip install blockstack --upgrade

EXPOSE 6264

CMD blockstack-core --debug start

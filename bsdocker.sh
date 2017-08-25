#!/bin/bash

# This script provides a simple interface for folks to use the docker install

image=quay.io/blockstack/blockstack-core:latest
# Local Blockstack directory
homedir=$HOME/.blockstack
# Blockstack Directory inside container
containerdir=/root/.blockstack
# Name of Blockstack API container
containername=blockstack-api

build () {
  echo "Building blockstack docker image. This might take a minute..."
  docker build -t $image .
}

setup () {
  if [ $# -eq 0 ]; then
    echo "Need to input new wallet password when running setup: ./bsdocker setup mypass"
    exit 1
  fi
  docker run -it -v $homedir:$containerdir $image blockstack setup -y --password $1
  
  # Use init containers to set the API bind to 0.0.0.0
  docker run -it -v $homedir:$containerdir $image sed -i 's/api_endpoint_bind = localhost/api_endpoint_bind = 0.0.0.0/' $containerdir/client.ini
  docker run -it -v $homedir:$containerdir $image sed -i 's/api_endpoint_host = localhost/api_endpoint_host = 0.0.0.0/' $containerdir/client.ini
}

start () {
  # Check for args first
  if [ $# -eq 0 ]; then
    echo "Need to input password for wallet located in the $HOME/.blockstack folder when staring api: ./bsdocker start mypass"
    exit 1
  fi
  
  # Check for the blockstack-api container is running or stopped. 
  if [ "$(docker ps -q -f name=blockstack-api)" ]; then
    echo "container is already running"
    exit 1
  elif [ ! "$(docker ps -q -f name=blockstack-api)" ]; then
    if [ "$(docker ps -aq -f status=exited -f name=blockstack-api)" ]; then
      # cleanup old container if its still around
      echo "removing old container..."
      docker rm $containername
    fi
    
    # If there is no existing blockstack-api container, run one
    # Linux needs to mount /tmp:/tmp
    if [[ $(uname) == 'Linux' ]]; then
      docker run -d --name $containername -v $homedir:$containerdir -v /tmp/:/tmp/ -p 6270:6270 $image blockstack api start-foreground --password $1 --api_password $1 --debug
    elif [[ $(uname) == 'Darwin' ]]; then
      docker run -d --name $containername -v $homedir:$containerdir -p 6270:6270 $image blockstack api start-foreground --password $1 --api_password $1 --debug
    fi
  fi

}

stop () {
  echo "stopping the running blockstack-api container"
  docker stop $containername && docker rm $containername
}

enter () {
  echo "entering docker container"
  docker exec -it $containername /bin/bash
}

logs () {
  echo "streaming logs for blockstack-api container"
  docker logs $containername -f
}

push () {
  echo "pushing build container up to quay.io..."
  docker push $image
}

commands () {
  cat <<-EOF
bsdocker commands:
  start -> start the blockstack api server
  stop -> stop the blockstack api server
  setup -> run the setup for blockstack and generate a wallet
  logs -> access the logs from the blockstack api server
  build -> build the docker image for running the api server
  enter -> exec into the running docker container
EOF
}

case $1 in
  setup)
    setup $2
    ;;
  stop)
    stop
    ;;
  logs)
    logs
    ;;
  build)
    build 
    ;;
  enter)
    enter 
    ;;
  start)
    start $2
    ;;
  push)
    push
    ;;
  *)
    commands
    ;;
esac

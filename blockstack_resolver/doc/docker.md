Instructions for Docker
=======

## Basic:

The easiest way to run the resolver is by running a full-node docker (a full-node has a local namecoin daemon running inside the docker). On debian/ubuntu you can use:

> sudo docker run -d -p 80:80/tcp digitalpassport/resolver

## Installing Docker on Debian:

If you don't have docker already installed, you can install it by:

```
sudo apt-get update
sudo apt-get install -y docker.io
. ~/.bashrc
sudo docker run -d -p 80:80/tcp digitalpassport/resolver
```

## Installing Docker on OS X:

If you want to run this on OS X, you can install docker by:

```
brew install docker
brew install boot2docker
boot2docker init
boot2docker up
docker run -d -p 80:80/tcp digitalpassport/resolver
```

Docker on OS X has a time sync issue that affects namecoind. Run:

> /usr/local/bin/boot2docker ssh sudo ntpclient -s -h pool.ntp.org

To manually sync the clock before running the resolver docker. Also, on OS X the docker is running inside virtualbox which means you will not be able to talk to the resolver on http://localhost. Instead:

> boot2docker ip

Will give you the IP address of the VM e.g., 192.168.59.103 and you can then use http://192.168.59.103 to talk to the resolver.
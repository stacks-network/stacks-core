Instructions for Docker
=======

## Basic:

The easiest way to run the resolver is by running a full-node docker (a full-node has a local namecoin daemon running inside the docker). On debian/ubuntu you can use:

> sudo docker run -d -p 80:80/tcp blockstack/resolver

## With SSL 

We highly recommend using the resolver with SSL. Here are steps to generate a self-signed certificate

```
sudo apt-get install openssl
mkdir localcerts
openssl req -new -x509 -days 365 -nodes -out localcerts/apache.pem -keyout localcerts/apache.key
chmod 600 localcerts/apache*
```

After generating the self-signed certificate (on the host), you can mount the localhosts directory in the docker and run the resolver docker as: 

> sudo docker run -d -p 80:80/tcp -p 443:443/tcp -v /path/to/localcerts:/etc/ssl/localcerts blockstack/resolver-ssl

This will enable the resolver to listen for both http and https traffic. Make sure to **edit the /path/to/localcerts** for your directory accordingly before running the above line. 

## Installing Docker on Debian:

If you don't have docker already installed, you can install it by:

```
sudo apt-get update
sudo apt-get install -y docker.io
. ~/.bashrc
sudo docker run -d -p 80:80/tcp blockstack/resolver
```

## Installing Docker on OS X:

If you want to run this on OS X, you can install docker by:

```
brew install docker
brew install boot2docker
boot2docker init
boot2docker up
docker run -d -p 80:80/tcp blockstack/resolver
```

Docker on OS X has a time sync issue that affects namecoind. Run:

> /usr/local/bin/boot2docker ssh sudo ntpclient -s -h pool.ntp.org

To manually sync the clock before running the resolver docker. Also, on OS X the docker is running inside virtualbox which means you will not be able to talk to the resolver on http://localhost. Instead:

> boot2docker ip

Will give you the IP address of the VM e.g., 192.168.59.103 and you can then use http://192.168.59.103 to talk to the resolver.

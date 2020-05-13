#!/bin/sh

apt-get update
mkdir ~/.ssh
mkdir -p /var/run/sshd
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
echo $pub_key >> ~/.ssh/authorized_keys
apt-get install -y openssh-server
chmod 600 /etc/ssh/ssh_host_*
exec /usr/sbin/sshd -D
/node/stacks-blockchain/target/debug/stacks-node neon

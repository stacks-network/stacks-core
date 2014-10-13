#!/bin/bash

echo "Enter API_USERNAME:"
read input
export API_USERNAME=$input

echo "Enter API_PASSWORD:"
read input
export API_PASSWORD=$input

echo "Enter NAMECOIND_SERVER:"
read input
export NAMECOIND_SERVER=$input

echo "Enter NAMECOIND_PORT:"
read input
export NAMECOIND_PORT=$input

echo "Enter NAMECOIND_USER:"
read input
export NAMECOIND_USER=$input

echo "Enter NAMECOIND_PASSWD:"
read input
export NAMECOIND_PASSWD=$input

echo "Done"
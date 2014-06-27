#!/bin/bash
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

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

echo "Enter WALLET_PASSPHRASE:"
read input
export WALLET_PASSPHRASE=$input

echo "Enter LOAD_BALANCER:"
read input
export LOAD_BALANCER=$input

echo "Enter MONGODB_URI:"
read input
export MONGODB_URI=$input

echo "Done"
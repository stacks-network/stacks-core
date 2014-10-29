#!/bin/bash
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

echo "Enter MONGODB_URI:"
read input
export MONGODB_URI=$input

echo "Enter OLD_DB:"
read input
export OLD_DB=$input

echo "Enter FRONTEND_APP_SECRET:"
read input
export FRONTEND_APP_SECRET=$input

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

echo "Enter NAMECOIND_WALLET_PASSPHRASE:"
read input
export NAMECOIND_WALLET_PASSPHRASE=$input

echo "Done"
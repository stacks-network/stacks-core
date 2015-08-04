#!/bin/bash

echo "Enter BITCOIND_SERVER:"
read input
export BITCOIND_SERVER=$input

echo "Enter BITCOIND_PORT:"
read input
export BITCOIND_PORT=$input

echo "Enter BITCOIND_USER:"
read input
export BITCOIND_USER=$input

echo "Enter BITCOIND_PASSWD:"
read input
export BITCOIND_PASSWD=$input

echo "Enter BITCOIND_WALLET_PASSPHRASE:"
read input
export BITCOIND_WALLET_PASSPHRASE=$input

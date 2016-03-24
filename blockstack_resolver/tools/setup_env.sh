#!/bin/bash

echo "Enter BLOCKSTACKD_IP:"
read input
export BLOCKSTACKD_IP=$input

echo "Enter BLOCKSTACKD_PORT:"
read input
export BLOCKSTACKD_PORT=$input

echo "Enter DHT_MIRROR_IP:"
read input
export DHT_MIRROR_IP=$input

echo "Enter DHT_MIRROR_PORT:"
read input
export DHT_MIRROR_PORT=$input

echo "Done"
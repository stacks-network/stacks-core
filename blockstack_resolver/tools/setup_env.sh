#!/bin/bash

echo "Enter BLOCKSTORED_IP:"
read input
export BLOCKSTORED_IP=$input

echo "Enter BLOCKSTORED_PORT:"
read input
export BLOCKSTORED_PORT=$input

echo "Enter DHT_MIRROR_IP:"
read input
export DHT_MIRROR_IP=$input

echo "Enter DHT_MIRROR_PORT:"
read input
export DHT_MIRROR_PORT=$input

echo "Done"
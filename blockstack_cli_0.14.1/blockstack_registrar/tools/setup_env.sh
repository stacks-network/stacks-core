#!/bin/bash

echo "Enter WEBAPP_DB_URI:"
read input
export WEBAPP_DB_URI=$input

echo "Enter API_DB_URI:"
read input
export API_DB_URI=$input

echo "Enter QUEUE_DB_URI:"
read input
export QUEUE_DB_URI=$input

echo "Enter BTC_PRIV_KEY:"
read input
export BTC_PRIV_KEY=$input

echo "Done"
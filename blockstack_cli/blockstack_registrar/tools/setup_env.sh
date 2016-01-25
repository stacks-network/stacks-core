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

echo "Enter SECRET_KEY:"
read input
export SECRET_KEY=$input

echo "Enter HD_WALLET_PRIVKEY:"
read input
export HD_WALLET_PRIVKEY=$input

echo "Done"
#!/bin/bash

echo "Enter MONGODB_URI:"
read input
export MONGODB_URI=$input

echo "Enter AWSDB_URI:"
read input
export AWSDB_URI=$input

echo "Enter MONGOLAB_URI:"
read input
export MONGOLAB_URI=$input

echo "Enter FRONTEND_SECRET:"
read input
export FRONTEND_SECRET=$input

echo "Done"
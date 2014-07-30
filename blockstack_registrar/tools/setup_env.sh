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

echo "Done"
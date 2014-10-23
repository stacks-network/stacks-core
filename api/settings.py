# -*- coding: utf-8 -*-
"""
	Onename API
	Copyright 2014 Halfmoon Labs, Inc.
	~~~~~
"""

import os

if 'DYNO' in os.environ:
	# Debugging
	DEBUG = False

	# Database
	MONGODB_DB = 'heroku_app30954501'
	MONGODB_USERNAME = 'heroku_app30954501'
	MONGODB_HOST = 'ds047930.mongolab.com'
	MONGODB_PORT = 47930

	# Secret settings
	for env_variable in os.environ:
		env_value = os.environ[env_variable]
		exec(env_variable + " = '" + env_value + "'")

	MONGODB_URI = MONGOLAB_URI

else:
	APP_URL = 'localhost:5000'

	# Debugging
	DEBUG = True

	# Database
	MONGODB_DB = 'heroku_app30954501'
	MONGODB_USERNAME = 'heroku_app30954501'
	MONGODB_HOST = 'ds047930.mongolab.com'
	MONGODB_PORT = 47930

	# Secret settings
	from .secrets import *

	MONGODB_URI = 'mongodb://' + MONGODB_USERNAME + ':' + MONGODB_PASSWORD  + '@' + MONGODB_HOST + ':' + str(MONGODB_PORT) + '/' + MONGODB_DB

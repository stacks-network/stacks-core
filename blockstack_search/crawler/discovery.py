#!/usr/bin/env python
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import json
from flask import Flask, render_template
from common import pretty_dump, error_reply

app = Flask(__name__)

#-----------------------------------
@app.route('/')
def index():

	from datetime import datetime 
	time = datetime.now()
	return render_template('discovery.html',time=time.strftime('%X'))

#-----------------------------------
@app.route('/poll/<string:target>', methods = ['GET'])
def poll_target(target):

	reply = {}

	blocks = '270941'

	if(target == 'blockchain'):
		reply['status'] = 1
		reply['message'] = "Refreshed discovery_queue from source 'bitcoin blockchain'. Latest blocks: " + blocks 

	elif(target == 'crawlindex'):
		from datetime import datetime, timedelta
		diff = timedelta(hours=24)

		last_crawled = datetime.now() - diff 

		reply['status'] = 1
		reply['message'] = "Refreshed discovery_queue from source 'crawl index'. Oldest crawled URL: " + last_crawled.strftime('%Y-%m-%d %X')

	else:
		reply = "Target '" + target + "' not recognized"
		return error_reply(reply)

	return pretty_dump(reply)

#-----------------------------------
@app.errorhandler(500)
def internal_error(error):

	return error_reply("Something went wrong with the server")

#-----------------------------------
@app.errorhandler(404)
def internal_error(error):

	return error_reply('URL not found on this server')

#------------------
if __name__ == '__main__':
	app.run(debug=True)

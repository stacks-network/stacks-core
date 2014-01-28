#!/usr/bin/env python
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import json
from flask import Flask, render_template, request
from common import pretty_dump, error_reply
import requests

app = Flask(__name__)
app.config.from_object('config')

from pymongo import MongoClient
c = MongoClient()

fg = c['freegraph']

#-------------------------
def get_domain_from_url(url):
    
    from urlparse import urlparse

    o = urlparse(url)

    domain = o.hostname

    return domain.lower()

#-------------------------
def check_host_url_inner(url):

	#headers = {'Content-type': 'application/json', 'Accept': 'text/plain', 'Authorization': 'Basic'}

	print "checking: " + url 

	try:
		r = requests.get(url)
	except:
		return False, None

	print r.status_code

	if(r.status_code == 200):
		try:
			data = r.json() 
		except:
			return False, None

		if 'users' in data.keys():
			return True, data 
	else:
		return False, None 

#-------------------------
def check_host_url(domain):

	check_urls = [] 
	check_servers = []

	check_servers.append(domain)

	for i in app.config['SUBDOMAINS']:
		check_servers.append(i + '.' + domain)

	for server in check_servers:

		for port in app.config['SCANPORTS']:
			check_urls.append('http://' + server + ':' + port + app.config['FG_API_SLUG'])

	for url in check_urls:
		reply, data = check_host_url_inner(url)
		if(reply):
			return url, data  

	return False, None 

#-----------------------------------
@app.route('/')
def index():

	return render_template('index.html')

#-----------------------------------
@app.route('/host', methods=['GET'])
def get_host():

	try:
		input_url = request.values['url']

		#check if 'http' or 'https' was entered, if not then append 'http' 
		if((input_url.find('http://') == -1) and (input_url.find('https://') == -1)):
			input_url = 'http://' + input_url
		
	except:
		return error_reply("No URL given")

	domain = get_domain_from_url(str(input_url))

	host_url, data = check_host_url(domain)
	nodes = []

	if(host_url is not False):
		reply = fg.hosts.find_one({'domain':domain})

		if(reply):
			fg.hosts.remove(reply)

		host = {}
		host['domain'] = domain 
		host['host_url'] = host_url
		host['data'] = data
		fg.hosts.insert(host)

		nodes = data['users'].keys() 

		print nodes 

		for username in nodes:

			node = {}
			node['node_url'] = host_url + '/' + username

			reply = fg.nodes.find_one({'node_url':node['node_url']})

			if(reply):
				fg.nodes.remove(reply)
			
			node['data'] = requests.get(node['node_url']).json()

			try:
				full_name = node['data']['name']['first'].lower() + ' ' + node['data']['name']['last'].lower()
			except:
				node['full_name'] = ""
			else:
				node['full_name'] = full_name

			fg.nodes.insert(node)

	return render_template('node.html',domain=domain,host_url=host_url,nodes=nodes)

#------------------
if __name__ == '__main__':
	app.run(debug=app.config['DEBUG'], port=app.config['PORT'])

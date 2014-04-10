
#!/usr/bin/env python
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

'''
	Developer  API -- powers onename Search  
'''

from flask import request, jsonify, Flask

from search_api import get_people

from helpers import *

app = Flask(__name__)

#----------------------------------------------
@app.route('/v1/people-search', methods = ['GET'])
def search_people():

	#1. verify key
	#is_key_valid(request.values['access_token'])
	
	#use the access token to generate the key

	#2. verify available quota
	#is_overquota(username)
	
	#3. add error handling

	query = request.values['keywords']

	results = get_people(query)

	return results

#----------------------------------------------
if __name__ == '__main__':

	app.run(debug=True, port=5003)


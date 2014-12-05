import os, json, requests, traceback

from ..errors import APIError, ProfileNotFoundError, BadProfileError, \
	UsernameTakenError

from .examples import EXAMPLES
from commontools import log, get_json
from ..settings import USERDB_URI

#-----------------------------------
from pymongo import MongoClient

remote_client = MongoClient(USERDB_URI)
remote_db = remote_client.get_default_database()
users = remote_db.user

#-----------------------------------------
def get_blockchain_profile(username):

	auth = ('opennamesystem', 'opennamesystem')
	BASE_URL = 'http://ons-server.halfmoonlabs.com/ons/profile?openname='

	if username == 'example-ryanshea' or username == 'example':
		return EXAMPLES['ryanshea']

	try:
		r = requests.get(BASE_URL + username, timeout=1, auth=auth)
	except requests.exceptions.ConnectionError:
		raise ProfileNotFoundError("User doesn't seem to exist.")
	except requests.exceptions.Timeout:
		raise ProfileNotFoundError("User doesn't seem to exist.")

	if r.status_code == 404:
		raise ProfileNotFoundError("User not found.")
	else:
		try:
			profile = json.loads(r.text)
		except ValueError:
			raise BadProfileError("User data not properly formatted.")

	if not profile:
		raise BadProfileError("User profile is empty.")

	if 'message' in profile and not ('name' in profile or 'v' in profile):
		raise UsernameTakenError(profile['message'])

	return profile

#-----------------------------------------
def get_db_profile(username):

	try: 
		user = users.find_one({"username":username})
		profile = get_json(user["profile"])

	except Exception as e:
		profile = None
		log.error("couldn't connect to database")
		
	return profile
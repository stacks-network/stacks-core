from flask import Flask, jsonify
from pymongo import Connection

app = Flask(__name__)

con = Connection()
db = con['onename_graph']    #selects the DB
user_graph = db.user_graph   #user_graph collection 

#-----------------------
@app.route("/")
def index():
    return "Welcome to followers API"

#-----------------------
@app.route("/v1/users/<username>/followers")
def get_followers(username):

	#lookup the user in the db
	user = user_graph.find_one({'name': 'u/' + username})
	followers = []

	if user.get('followers') is None:
		return []

	for follower in user.get('followers'):
		followers.append({'username': follower})

	return jsonify({'followers': followers})	

#-----------------------
if __name__ == "__main__":
    app.run(debug=True)
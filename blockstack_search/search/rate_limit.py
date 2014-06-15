from hashlib import md5
import time
from pymongo import MongoClient

c = MongoClient()
db = c['developers']
nodes = db.nodes

MAX_QUOTA = 1000

#-------------------------------------------------------------
def generate_key(username):
    """Receives username/email as input and generate md5 hash key of the input"""

    hash_input = username + str(time.time())
    key = md5(hash_input).hexdigest()
        
    return key 

#-------------------------------------------------------------        
def validate_token(access_token):
    """Checks if a 'key' is valid"""

    if access_token == None:
        return False

    return nodes.find({'api_key' : access_token}).limit(1).count()

#-------------------------------------------------------------        
def verify_and_decrement_quota(access_token):
    """Returns False if quota associated with 'username' has expired and Decrements quota otherwise"""

    user = nodes.find_one({'api_key' : access_token})

    if user['api_quota'] < 1:
        return False
    else:
        decrement_quota(access_token)
        return True

#--------------------------------------
def decrement_quota(access_token):
    """Decrement API quota associated with the 'username'"""
    
    user = nodes.find_one({'api_key' : access_token})

    user['api_quota'] = user['api_quota'] - 1
    
    nodes.save(user)

#--------------------------------------
def initialize_quota(username):
    """Initialize quota for a specific username to some starting value such as 1000 """

    user = nodes.find_one({'username' : username})

    user['api_quota'] = MAX_QUOTA
    nodes.save(user)

#--------------------------------------
def reset_all_quota():
    """Reset (initialize) quota for all the users"""

    users = nodes.find()
    
    for user in users:
        user['api_quota'] = MAX_QUOTA
        nodes.save(user)

#--------------------------------------
def save_user(username, account_type):

    """create a new user (developer) given a username and account_type"""

    user = {}
    user['username'] = username
    user['account_type'] = account_type
    user['api_key'] = generate_key(username)
    user['api_quota'] = MAX_QUOTA

    nodes.save(user)

    return user['api_key']
#--------------------------------------

#Test

if __name__ == '__main__':
    
    #cleaning...
    nodes.drop()

    #generate random key
    print generate_key('ibrahim')

    #create new developer given a onename username
    save_user('ibrahim', 'basic')

    #print this user
    print nodes.find_one({'username' : 'ibrahim'})

    #decrement the user quota
    decrement_quota('ibrahim')

    #print the user again
    print nodes.find_one({'username' : 'ibrahim'})

    #initialize the user quota
    initialize_quota('ibrahim')

    #print the user again
    print nodes.find_one({'username' : 'ibrahim'})

    #decrement the user quota again
    decrement_quota('ibrahim')

    #print the user again
    print nodes.find_one({'username' : 'ibrahim'})

    #reset all quota
    reset_all_quota()

    #print the user again
    print nodes.find_one({'username' : 'ibrahim'})



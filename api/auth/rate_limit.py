# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

import time, datetime
from hashlib import md5

from ..db import db

nodes = db.nodes

MAX_QUOTA = 25

#---------------------
#Account Creation 
#---------------------
def save_user(username, account_type):

    """ used for temporary Token generation. (to be replaced)
    create a new user (developer) given a username and account_type
    """

    user = {}
    user['username'] = username
    user['account_type'] = account_type
    user['access_token'] = generate_token(username)
    user['api_quota'] = MAX_QUOTA
    user['last_call'] = datetime.datetime.now()

    nodes.save(user)

    return user['access_token']
#-------------------------------------------------------------
def generate_token(username):
    """Receives username/email as input and generate md5 hash key of the input"""

    hash_input = username + str(time.time())
    access_token = md5(hash_input).hexdigest()
        
    return access_token  

#----------------------------------------------      
def validate_token(access_token):
    """Checks if a 'key' is valid"""

    if access_token == None:
        return False

    return nodes.find({'access_token' : access_token}).limit(1).count()

#---------------------
#Token Validation 
#---------------------
def initialize_quota(username):
    """Initialize quota for a specific username to some starting value such as 1000 """

    user = nodes.find_one({'username' : username})

    user['api_quota'] = MAX_QUOTA
    nodes.save(user)

#--------------------------------------    
def decrement_quota(access_token):
    """returns False if quota associated with 'username' has expired. other
    otherwise decrements quota"""

    user = nodes.find_one({'access_token' : access_token})

    if user['api_quota'] < 1:
        return False
   
    else:
        user = nodes.find_one({'access_token' : access_token})

        time_now = datetime.datetime.now()

        difference = time_now - user['last_call']

        difference = divmod(difference.days * 86400 + difference.seconds, 60) #format: 0 minutes, 8 seconds

        #reset if 15mins have passed since the last call
        if difference[0] > 14:
            reset_quota(user)

        user['last_call'] =  datetime.datetime.now()
        user['api_quota'] = user['api_quota'] - 1

        nodes.save(user)
        
        return True

#--------------------------------------
def reset_quota(user):
    """Reset (initialize) quota for all the users"""
    
    user['api_quota'] = MAX_QUOTA
    
    nodes.save(user)

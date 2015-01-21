#!/usr/bin/env python

#----------------------------
# NOTE: outdated client 
#----------------------------


import json
import requests

class OneName:

    profile_url = 'http://162.243.106.239:5005/v1/people/'
    search_url = 'http://162.243.106.239:5005/v1/people-search/'
    access_token = ''

    def __init__(self, access_token):
        self.access_token = access_token

    def get_access_token(self):
        return self.access_token
    
    def get_profile(self, onename_id):
        url = self.profile_url + "?onename_id=" + onename_id + "&access_token=" + self.access_token
        resp = requests.get(url)
        return resp.text

    def search(self, query):
        url = self.search_url + "?keywords=" + query + "&access_token=" + self.access_token
        resp = requests.get(url)
        return resp.text

#------------------------------
##############Main#############
#------------------------------

access_token = '35dd5f7b87ffd7580afd120f90473674'
api = OneName(access_token)

print api.get_profile('muneeb')
print "\n#--------------------"
print api.search('ryan')

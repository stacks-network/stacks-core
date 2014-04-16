import json
import requests

class OneName:

    profile_url = 'http://162.243.106.239:5005/v1/people/'
    search_url = 'http://162.243.106.239:5005/v1/people-search/'

    def __init__(self):
        pass

    def get_profile(self, onename_id):
        url = self.profile_url + "id=" + onename_id 
        resp = requests.get(url)
        return resp.text

    def search(self, query, accesss_token):
        url = self.search_url + access_token + "?keywords=" + query
        resp = requests.get(url)
        return resp.text

#------------------------------
##############Main#############
#------------------------------

access_token = '35dd5f7b87ffd7580afd120f90473674'
api = OneName()

print api.get_profile('muneeb')
print "\n#-------------------------------------------------------------------"
print api.search('ryan', access_token)

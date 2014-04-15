import json
import requests

PROFILE_URL = 'http://localhost:5003/v1/people/'
SEARCH_URL = 'http://localhost:5003/v1/people-search/'
ACCESS_TOKEN = '<ACCESS_TOKEN>'

#Profile API
query = 'muneeb'
url = PROFILE_URL + "id=" + query 
resp = requests.get(url)
print resp.text

#SEARCH API
query = 'john '
url = SEARCH_URL + ACCESS_TOKEN + "?keywords=" + query
resp = requests.get(url)
print resp.text
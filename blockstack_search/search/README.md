# OneName Search

### Requirements:

### Elastic Search

Elastic Search library is not in github and resides at

unix/lib/elastic

the current version we're using is *0.90.2*. Download from:

> wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-0.90.2.zip

#### requirements.txt files has been updated and contains all the project requriements.

Notes:
before installing pylimbmc make sure libmemcache is installed:


      brew install libmemcached
      pip install pylibmc 

----------------------------------------------

Create Index: 
	
> python create_search_index.py --create_index


Note: Make sure mongodb and elastic search are running before creating index

To test if elastic search is running:

	curl -X GET http://localhost:9200/

{
  "ok" : true,
  "status" : 200,
  "name" : "Angler",
  "version" : {
    "number" : "0.90.2",
    "snapshot_build" : false,
    "lucene_version" : "4.3.1"
  },


----------------------------------------------
API usage:
----------------------------------------------

### Generate Developer key:

Request parameters:

Developer ID needs to be passed

Sample Request: 

> curl -G http://localhost:5003/v1/gen_developer_key/ -d "developer_id=asjad"

Sample Response:

	{
  	  "access_token": "bba1e70e7af8bba213c52d6d9abe3389", 
	  "developer_id": "asjad"
	}


### Search API (powered by elastic search)

syntax: 

> {machineip}/v1/people-search/<access_token>?keywords={keywords}

EXAMPLE Usage:

using username:

> curl -G http://localhost:5003/v1/people-search/a0fe2f40415f7451c4ba2eae7da963d5 -d "keywords=muneeb"

using btc_address:

> curl -G http://localhost:5003/v1/people-search/a0fe2f40415f7451c4ba2eae7da963d5 -d "keywords=1G6pazv8zjWKBWouXVgHHvgmRmSm7JmH3S"

using twitter handle:

> curl -G http://localhost:5003/v1/people-search/a0fe2f40415f7451c4ba2eae7da963d5 -d "keywords=ryaneshea"

### keywords can accept username, twitter handle and btc

Sample Response:

-------------------------------------------------------
{
  "people": [
    {
      "avatar": {
        "url": "http://muneebali.com/static/img/muneebali_thumb.jpg"
      }, 
      "bio": "CTO at HalfmoonLabs. PhD candidate at Princeton. Interested in distributed systems and cryptocurrencies (like Bitcoin)", 
      "bitcoin": {
        "address": "1G6pazv8zjWKBWouXVgHHvgmRmSm7JmH3S"
      }, 
      "cover": {
        "url": "http://muneebali.com/static/img/ny_skyline.jpg"
      }, 
      "github": {
        "username": "muneeb-ali"
      }, 
      "instagram": {
        "username": "muneeb"
      }, 
      "linkedin": {
        "url": "http://linkedin.com/in/muneebali"
      }, 
      "location": {
        "formatted": "New York"
      }, 
      "name": {
        "formatted": "Muneeb Ali"
      }, 
      "twitter": {
        "username": "muneeb"
      }, 
      "v": "0.2", 
      "website": "http://muneebali.com"
    }
  ]
}


-------------------------------------------------------

** Experimental syntax for search queries ** (using the same backend implementation)

	curl -i http://localhost:5003/v1/people-search/a0fe2f40415f7451c4ba2eae7da963d5?full-name=Muneeb Ali
	curl -i http://localhost:5003/v1/people-search/a0fe2f40415f7451c4ba2eae7da963d5?twitter=ryaneshea
	curl -i http://localhost:5003/v1/people-search/a0fe2f40415f7451c4ba2eae7da963d5?btc_address=1G6pazv8zjWKBWouXVgHHvgmRmSm7JmH3S

3) Profile API (powered by mongodb)


Syntax: 

> {machine_ip}/v1/people/id={onename_id}

EXAMPLE:
	
> curl -G http://localhost:5003/v1/people/id=muneeb



----------------------------------------------
old Notes (to be deprecated):
----------------------------------------------


We currently have two search sub-systems to handle search queries:

* Substring search on people names (just from full_name of people)
* Search on the raw lucene index (build from entire OneName profiles)

We assume that the user is entering either a *person's name* OR some other data present in the profile e.g., twitter handle etc. The API expects an input of the format:

     {
          "query": "the search query/term",
          "limit_results": "numeric limit on number of results e.g., 50, this parameter is optional"
     }

The API returns a JSON object of the format:

     {
          "people": [ ]
     }

### Quick Testing

You can test the search API using curl:

> curl http://server_ip>/<path_to_api_endpoint> -G -d "query=fred%20wilson"

OR by using the [test_client.py](test_client.py)

> ./test_client.py "fred wilson"

Make sure that the packages listed in requirements.txt are installed before using the test_client.py

This will currently return upto a max of 20 results (can be less depending on the query) with data that follows structure of OneName profiles described here:

https://github.com/onenameio/onename

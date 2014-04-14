# OneName Search

### Elastic Search

Elastic Search library is not in github and resides at

unix/lib/elastic

the current version we're using is *0.90.2*. Download from:

> wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-0.90.2.zip


### Requirements:

requirements.txt files has been updated and contains all the project requriements.

Notes:
before installing pylimbmc make sure libmemcache is installed:


      brew install libmemcached
      pip install pylibmc 

----------------------------------------------

Create Index: 
	python create_search_index.py --create_index


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
  "tagline" : "You Know, for Search"



----------------------------------------------
API usage:
----------------------------------------------

1) Generate Developer key:


syntax: <machine_ip:port>/v1/gen_developer_key/<developer_id>

Example: 

	curl -i http://localhost:5003/v1/gen_developer_key/asjad


----------------------------------------------
2) Search API (powered by elastic search)
----------------------------------------------

syntax: <machine_ip>/v1/people-search/<developer_id>/<access_token>?keywords='<keywords>'

EXAMPLE:

using username:
	curl -i http://localhost:5003/v1/people-search/asjad/a0fe2f40415f7451c4ba2eae7da963d5?keywords=ryan

using btc_address:

	curl -i http://localhost:5003/v1/people-search/asjad/a0fe2f40415f7451c4ba2eae7da963d5?keywords=1G6pazv8zjWKBWouXVgHHvgmRmSm7JmH3S 


 > keywords can accept username, twitter handle and btc

* Experimental *:

	http://localhost:5003/v1/people-search/asjad/a0fe2f40415f7451c4ba2eae7da963d5?full-name = Muneeb Ali
	http://localhost:5003/v1/people-search/asjad/a0fe2f40415f7451c4ba2eae7da963d5?twitter = muneeb
	http://localhost:5003/v1/people-search/asjad/a0fe2f40415f7451c4ba2eae7da963d5?btc = muneeb

----------------------------------------------
3) Profile API (powered by mongodb)
----------------------------------------------

Syntax:
	 <machine_ip>/v1/people/id=<onename_id>

EXAMPLE:

	curl -i http://localhost:5003/v1/people/id=muneeb



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

> curl http://<server_ip>/<path_to_api_endpoint> -G -d "query=fred%20wilson"

OR by using the [test_client.py](test_client.py)

> ./test_client.py "fred wilson"

Make sure that the packages listed in requirements.txt are installed before using the test_client.py

This will currently return upto a max of 20 results (can be less depending on the query) with data that follows structure of OneName profiles described here:

https://github.com/onenameio/onename
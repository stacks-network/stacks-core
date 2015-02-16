#opename-search
========

about:

Search API for OpenName

Currently has two search sub-systems to handle search queries:

* Substring search on people usernames,full names,twitter_handle(powered by mongodb)
* raw lucene index which handles profile bio search

Search will currently return upto a max of 20 results (can be less depending on the query) with data that follows structure of OneName profiles described here:

https://github.com/onenameio/onename

### Requirements:
---------------------
	
	sudo apt-get install mongodb
	sudo apt-get install memcached libmemcached-dev
	sudo apt-get install python2.7-dev
	pip install -r requirements.txt 

You'll also need to install elastic search:

on mac:
	brew install elasticsearch(requires java sdk)


Ensure that mongodb and elastic search are running 
starting elastic search:


     just enter
     	 $elasticsearch (on mac)
     	 bin/elasticsearch -d(on linux)

To test if elastic search is running:

     curl -X GET http://localhost:9200/

returns:

{
  "ok" : true,
  "status" : 200,
  "name" : "Angler",
  "version" : {
    "number" : "0.90.2",
    "snapshot_build" : false,
    "lucene_version" : "4.3.1"
  },

###creating index:

	python search/substring_search.py --create_index
	python create_search_index --create index

###Quick Testing

Using search from command line
---------------------

	python search/substring_search.py --search_name "Fred Wil"
	python search/substring_search.py --search_twitter fredwil


API usage:

	curl -G {machine_ip}:port/search/name -d "query=ryan" 

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


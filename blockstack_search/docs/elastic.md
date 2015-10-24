## Docs for Elastic Search

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

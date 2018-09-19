---
layout: core
permalink: /:collection/:path.html
---
# How to build a Profile Search Index

The search subsystem for Blockstack Core creates an index for data associated
with registered names in namespaces and makes that data searchable.

The search subsystem is currently meant to index the .id namespace but can
be easily expanded to include other namespaces.

Currently there are two types of indexes to handle search queries:

* Substring search on usernames, full names, twitter_handle (powered by MongoDB)
* Raw Lucene index which handles searching extended data e.g., bio.

Search will currently return upto a max of 20 results (can be less depending on the query)
with data that follows structure of [blockstack IDs](https://github.com/blockstack/blockstack):

In early 2017, the search subsystem was ported over to the new API system, where support for search is provided by the endpoint:

```
http://localhost:5000/search?query=<SEARCH_PATTERN>
```

This document describes how to setup the search subsystem to respond at that endpoint.

# Installation

- **Step 1:** First, make sure you have [virtualenv installed](http://docs.python-guide.org/en/latest/dev/virtualenvs/).
Then, setup the API and search subsystem:
```
$ sudo apt-get install -y mongodb memcached python-dev libmemcached-dev zlib1g-dev nginx
$ sudo pip install uwsgi
$ git clone https://github.com/blockstack/blockstack-core.git --branch api
$ cd blockstack-core/
$ sudo pip install .
$ sudo pip install -r api/requirements.txt
$ sudo mkdir /var/blockstack-search && sudo chown $USER:$USER /var/blockstack-search
```

- **Step 2:** Make sure you have Blockstack Core running locally (see [instructions](https://github.com/blockstack/blockstack-core/blob/master/README.md#quick-start)). We highly
recommend using a local node because the search subsystem issues thousands of calls to
Blockstack Core for re-indexing and remote nodes can slow down performance.

- **Step 3:** Fetch the data for the .id namespace and respective profiles. Note, you may want to redirect stderr to a file, as there is a lot of debug output.

```
$ cd api/

$ python -m search.fetch_data --fetch_namespace

$ python -m search.fetch_data --fetch_profiles
```

- **Step 4:** Create the search index:

```
python -m search.basic_index --refresh
```

- **Step 5:** Enable search API endpoint:

```
$ sed -i 's/SEARCH_API_ENDPOINT_ENABLED \= False/SEARCH_API_ENDPOINT_ENABLED \= True/' config.py
```

# Usage

You can quickly test the search index from the command line:

```
python -m search.substring_search --search_name "Fred Wil"
python -m search.substring_search --search_twitter fredwil
```

You can also use the search API end-point:

> curl -G {machine_ip}:port/search/name -d "query=muneeb"

Sample Response:

```
{
  "people": [
   {
      "profile": {
          "website": [
          {
            "url": "http://muneebali.com",
            "@type": "WebSite"
          }
          ],
        "name": "Muneeb Ali",
        "address": {
          "addressLocality": "New York, NY",
          "@type": "PostalAddress"
        },
        "image": [
          {
            "contentUrl": "https://s3.amazonaws.com/dx3/muneeb",
            "@type": "ImageObject",
            "name": "cover"
          },
          {
            "contentUrl": "https://s3.amazonaws.com/kd4/muneeb",
            "@type": "ImageObject",
            "name": "avatar"
          }
        ],
        "@type": "Person",
        "description": "Co-founder of Blockstack. Interested in distributed systems and blockchains. Previously, PhD at Princeton."
    },
    "username": "muneeb"
    },
    {
      "profile": {
        "message": "This blockchain ID is reserved for Muneeb Ali. If this is you, please email support@onename.com to claim it for free.",
        "status": "reserved"
      },
      "username": "muneebali"
    },
    {
      "profile": {
        "cover": {
          "url": "https://s3.amazonaws.com/97p/HHE.jpg"
        },
        "v": "0.2"
      },
      "username": "muneebali1"
    }

  ]
}
```

## Enabling Elastic Search

### Requirements:

```
sudo apt-get install mongodb
sudo apt-get install memcached libmemcached-dev
sudo apt-get install python2.7-dev
pip install -r requirements.txt
```

### Elastic Search

Elastic Search library is not in github and resides at unix/lib/elastic

the current version we're using is *0.90.2*. Download from:

> wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-0.90.2.zip

before installing pylimbmc make sure [memcached]({{ site.baseurl }}/core/memcached.html) is installed.

Ensure that mongodb and elastic search are running
starting elastic search:

```
$elasticsearch (on mac)
bin/elasticsearch -d (on linux)
```

To test if elastic search is running:

> curl -X GET http://localhost:9200/

returns:

```
{
  "ok" : true,
  "status" : 200,
  "name" : "Angler",
  "version" : {
    "number" : "0.90.2",
    "snapshot_build" : false,
    "lucene_version" : "4.3.1"
  },
```

Create Index:

> python create_search_index.py --create_index

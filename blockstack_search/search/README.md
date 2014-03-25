# OneName Search

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

## Installing on UNIX

### Requirements

All required packages for Python are listed in 'requirements.txt'. In addition to those, also requires Elastic Search.

### Elastic Search

Elastic Search library is not in github and resides at

unix/lib/elastic

the current version we're using is *0.90.2*. Download from:

> wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-0.90.2.zip
> python scopesearch/create_search_index.py --create_people_index  
> python scopesearch/create_search_index.py --create_company_index

We'll simplify these steps in an upcoming release. We assume that both MongoDB and Elastic Search is running on the server. 

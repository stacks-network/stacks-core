# Scope Search

We currently have three search sub-systems to handle search queries:

* Substring search on people names
* Substring search on company names
* Search on the raw lucene index

We assume that the user is entering either a *person's name* OR a *company's name* in the search query. The API expects an input of the format:

     {
          "query": "the search query/term",
          "limit_results": "numeric limit on number of results e.g., 50, this parameter is optional"
     }

The API returns a JSON object of the format:

     {
          "companies": [],
          "people": []
     }

### Quick Testing

You can test the search API using curl:

> curl http://54.200.33.184/search/api/v1.0/people -G -d "query=peter%20thiel"

OR by using the [test_client.py](test_client.py)

> ./test_client.py "peter thiel"

Make sure that the packages listed in requirements.txt are installed before using the test_client.py

### Search API

#### People API 

The people API can be accessed via: 

> curl http://54.200.33.184/search/api/v1.0/people -G -d "query=peter%20thiel"

This will currently return upto a max of 20 results (can be less depending on the query) with the following data: 

* 'first_name'
* 'last_name'
* 'overview' -- overview of the person 
* 'companies' -- each company has 1) title of person, 2) name of company, and 3) permalink of company
* 'crunchbase_slug' -- this can be used to get the crunchbase URL as http://www.crunchbase.com/person/ + 'crunchbase_slug' 
* 'twitter_handle' -- twitter username 
* 'linkedin_url' -- linkedin URL 

#### Company API 

The company API can be accessed via: 

> curl http://54.200.33.184/search/api/v1.0/company -G -d "query=bank%20simple"

This will currently return upto a max of 20 results (can be less depending on the query) with the following data: 
     
* 'name' -- company name 
* 'homepage_url' -- company website 
* 'email_address' -- email, if given on crunchbase 
* 'email_info' -- has information on url_domain, email_domain and if can verify on them
* 'total_money_raised' -- the total $$ raised
* 'people' -- list of current employees 
* 'board' -- list of board members 
* 'overview' -- overview text from crunchbase
* 'tag_list' -- combination of tags and categories from crunchbase (crunchbase treats them separately, we don't)
* 'crunchbase_slug' -- this can be used to get the crunchbase URL as http://www.crunchbase.com/company/ + 'crunchbase_slug'
* 'offices' -- info on company office(s)
* 'acquisition' -- if acquired, the year it was acquired in 
        
## Installing on UNIX

### Requirements

All required packages for Python are listed in 'requirements.txt'. In addition to those, also requires Elastic Search.

### Elastic Search

Elastic Search library is not in github and resides at

unix/lib/elastic

the current version we're using is *0.90.2*. Download from:

> wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-0.90.2.zip

### Converting RAW data to search index

Right now, the steps required for going from raw data to "ready for searching" are: 

> python scope/datasets/crunchbase/filter_crunchbase_data.py --filter_people  
> python scope/datasets/crunchbase/filter_crunchbase_data.py --filter_company  
> python scopesearch/substring_search.py --create_cache  
> python scopesearch/create_search_index.py --create_people_index  
> python scopesearch/create_search_index.py --create_company_index

We'll simplify these steps in an upcoming release. We assume that both MongoDB and Elastic Search is running on the server. 

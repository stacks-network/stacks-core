#Search

The search subsystem for Blockstack Core creates an index for data associated
with registered names in namespaces and makes that data searchable.

The search subsystem is currently meant to index the .id namespace but can
be easily expanded to include other namespaces.

Currently there are two types of indexes to handle search queries:

* Substring search on usernames, full names, twitter_handle (powered by MongoDB)
* Raw Lucene index which handles searching extended data e.g., bio.

Search will currently return upto a max of 20 results (can be less depending on the query)
with data that follows structure of [blockstack IDs](https://github.com/blockstack/blockstack):

### Creating index:

```
python -m search.basic_index --refresh
```
### Quick Testing

Using search from command line

```
python -m search.substring_search --search_name "Fred Wil"
python -m search.substring_search --search_twitter fredwil
```

Usage:

> curl -G {machine_ip}:port/search/name -d "query=muneeb" 

Sample Response:

```
{
  "people": [
   {
      "profile": {
        "avatar": {
          "url": "https://s3.amazonaws.com/kd4/emadelwany"
        }, 
        "bio": "Co-founder @Onename (YC S14) w/ @Ryaneshea. Final-year PhD candidate @Princeton. Love NYC, coffee shops, and building things", 
        "bitcoin": {
          "address": "1DTRDHkWt3xyhrMCRHz1XV5DjCe9VxRoRW"
        }, 
        "cover": {
          "url": "https://s3.amazonaws.com/dx3/emadelwany"
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
        "website": "http://onename.com/muneeb"
      }, 
      "username": "emadelwany"
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

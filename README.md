API Usage
=========

### Generate Developer key:

Note: This method is temporary, and will be replaced by proper auth. mechanism. 

Request parameters:

unique Developer ID

Sample Request: 

> curl -G http://localhost:5000/onename/api/v1.0/gen_developer_key/ -d "developer_id=asjad"

Sample Response:

	{
  	  "access_token": "bba1e70e7af8bba213c52d6d9abe3389", 
	  "developer_id": "asjad"
	}


### Search API

Request parameters: 

> access_token and user_name (currently accepts username, twitter handle and btc_address)

syntax: 

> {machineip}/v1/people-search/?access_token={access_token}&name={keywords}

EXAMPLE Usage:

using username:

> curl -G http://localhost:5003/onename/api/v1.0/people-search/ -d "access_token=a0fe2f40415f7451c4ba2eae7da963d5&name=muneeb"

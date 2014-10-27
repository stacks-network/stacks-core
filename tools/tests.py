import json, requests

payload = {
	"profile": {
	  "graph": {
	    "url": "https://s3.amazonaws.com/grph/ryanshea"
	  }, 
	  "twitter": {
	    "proof": {
	      "url": "https://twitter.com/ryaneshea/status/486057647808868352"
	    }, 
	    "username": "ryaneshea"
	  }, 
	  "cover": {
	    "url": "https://s3.amazonaws.com/dx3/ryanshea"
	  }, 
	  "avatar": {
	    "url": "https://s3.amazonaws.com/97p/tux.jpg"
	  }, 
	  "website": "http://shea.io", 
	  "github": {
	    "proof": {
	      "url": "https://gist.githuåb.com/rxl/9799732"
	    }, 
	    "username": "rxl"
	  }, 
	  "name": {
	    "formatted": "Ryan Shea"
	  }, 
	  "facebook": {
	    "proof": {
	      "url": "https://facebook.com/ryaneshea/posts/10152385985597713"
	    }, 
	    "username": "ryaneshea"
	  },
	  "hackernews": {
	  	"proof": "https://news.ycombinator.com/user?id=rxl",
	  	"username": "rxl"
	  },
	  "stackoverflow": {
	  	"identifier": "1530754/ryan",
	  	"proof": "http://stackoverflow.com/users/1530754/ryan"
	  },
	  "instagram": {
	  	"identifier": "ryaneshea",
	  	"proof": "http://instagram.com/ryaneshea/"
	  },
	  "angellist": {
	  	"identifier": "ryanshea",
	  	"proof": "https://angel.co/ryanshea"
	  },
	  "linkedin": {
	  	"identifier": "ryaneshea",
	  	"proof": "https://www.linkedin.com/in/ryaneshea"
	  },
	  "reddit": {
	  	"identifier": "ryaneshea",
	  	"proof": "http://www.reddit.com/r/opennameproofs/comments/2k8r86/verifying_that_ryanshea_is_my_openname/"
	  },
	  "googleplus": {
	  	"identifier": "110166845166458482181",
	  	"proof": "https://plus.google.com/110166845166458482181/posts/2hYzHWTJi2V"
	  },
	  "bitcoin": {
	    "address": "14eautXfJT7EZsKfm1eHSAPnHkn3w1XF9R"
	  }, 
	  "pgp": {
	    "url": "https://s3.amazonaws.com/97p/pubkey.asc", 
	    "fingerprint": "DDA1CF3D659064044EC99354429E1A42A93EA312"
	  }, 
	  "location": {
	    "formatted": "New York, NY"
	  }, 
	  "bio": "Co-founder of OneName with @Muneeb. Bitcoin, identity, the blockchain, and decentralization.", 
	  "v": "0.2"
	},
	"openname": "ryanshea"
}

r = requests.post("http://localhost:5000/v1/verifications", data=json.dumps(payload))

print r.text

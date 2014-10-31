onename-search
========

Search API for OneName

Setting up a new server
---------------------
	
	sudo apt-get install mongodb
	sudo apt-get install memcached libmemcached-dev
	sudo apt-get install python2.7-dev
	pip install -r requirements.txt 
	python search/substring_search.py --create_index

Using search from command line
---------------------

	python search/substring_search.py --search_name "Fred Wil"
	python search/substring_search.py --search_twitter fredwil

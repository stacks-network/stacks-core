onename-search
========

Search API for OneName

Setting up a new server
---------------------
	
	sudo apt-get install mongodb
	sudo apt-get install memcached libmemcached-dev
	sudo apt-get install python2.7-dev
	pip install -r requirements.txt 
	python search/copy_user_db.py
	python search/substring_search.py --create_index


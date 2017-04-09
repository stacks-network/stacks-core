# Blockstack API 

Step-by-step instructions for deploying a Blockstack API node on Debian or 
Ubuntu are below.

- **Step 1:** Make sure you have Blockstack Core running locally (see [instructions](https://github.com/blockstack/blockstack-core/blob/master/README.md#quick-start)). 

- **Step 2:** Make sure you have [virtualenv installed](http://docs.python-guide.org/en/latest/dev/virtualenvs/). 
Then, setup the API:
``` 
$ sudo apt-get install -y python-pip memcached python-dev libmemcached-dev zlib1g-dev
$ sudo service memcached start
$ sudo pip install virtualenv
$ virtualenv api
$ git clone https://github.com/blockstack/blockstack-core.git
$ cd blockstack-core/
$ git checkout api
$ pip install -r api/requirements.txt
$ bin/blockstack api start
$ bin/blockstack-api
```

### Search Subsystem

If you want to enable the search subsystem in your installation, you can
follow the instructions [here](search.md).

### Nginx Deployment

For a production deployment we recommend using nginx and uwsgi:

- **Step 1:** Install nginx and uWSGI:
```
$ sudo apt-get install -y nginx
$ sudo pip install uwsgi
```
- **Step 2:** Copy [this sample nginx sites file](https://github.com/blockstack/blockstack-core/blob/api/api/nginx/config/nginx_sites-available/blockstack_api) to

> /etc/nginx/sites-available/blockstack_api

and edit the paths depending on your home directory. You can test your nginx settings:
```
$ sudo nginx -t
```
- **Step 3:** Copy [this sample systemd service file](https://github.com/blockstack/blockstack-core/blob/api/api/nginx/config/systemd_system/blockstack_api.service) to

> /etc/systemd/system/blockstack_api.service

and edit the paths depending on your home directory.

- **Step 4:** Get a security certificate from [Let's Encrypt](https://letsencrypt.org/).
```
$ git clone https://github.com/certbot/certbot.git
$ cd certbot/
$ ./certbot-auto --nginx -d <your_domain>
```

And copy the cert files to the path given in the nginx sites file earlier.

- **Step 5:** Start nginx and the Blockstack API:
```
sudo systemctl restart blockstack_api
sudo systemctl restart nginx
```

If you run into any issues, please [submit a Github issue](https://github.com/blockstack/blockstack-core/issues) and we'll update these
instructions.

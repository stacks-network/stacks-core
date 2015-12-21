## Production Server with Apache:

For running a production server, we recommend MOD_WSGI with Apache.

On Debian, first install dependencies:

```
sudo apt-get install -y apache2
sudo apt-get install -y libapache2-mod-wsgi
sudo apt-get install -y apache2-utils
sudo apt-get install -y apache2-dev
sudo pip install mod_wsgi
```

Then configure the server:
```
sudo mod_wsgi-express setup-server apache/apache.wsgi --port=80 --user www-data --group www-data --server-root=/etc/mod_wsgi-express-80 --httpd-executable=/usr/sbin/apache2 --processes=5
```

Now, you can start and stop the server with:
```
/etc/mod_wsgi-express-80/apachectl start
/etc/mod_wsgi-express-80/apachectl stop
```

For testing you can start the server on localhost:

> mod_wsgi-express start-server --port 5000